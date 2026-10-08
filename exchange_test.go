package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRequirementCodec(t *testing.T) {
	r := Requirement{Requirement: RequirementAuthToken, ResourceToken: "eyJx.y.z"}
	parsed, err := ParseRequirement(r.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != r {
		t.Fatalf("round trip: %+v != %+v", parsed, r)
	}
	// Spec example, unquoted whitespace variants.
	parsed, err = ParseRequirement(`requirement=interaction; url="https://ps.example/interaction"; code="A1B2-C3D4"`)
	if err != nil || parsed.URL != "https://ps.example/interaction" || parsed.Code != "A1B2-C3D4" {
		t.Fatalf("parsed %+v, %v", parsed, err)
	}
	// Values needing escapes survive a round trip as Strings.
	r = Requirement{Requirement: RequirementInteraction, URL: `https://ps.example/i?q="a\b"`, Code: "A1B2-C3D4"}
	if parsed, err = ParseRequirement(r.String()); err != nil || parsed != r {
		t.Fatalf("escaped round trip: %+v, %v", parsed, err)
	}
	// Unknown members and parameters are ignored.
	if parsed, err = ParseRequirement(`requirement=approval;x=1, other=?1`); err != nil || parsed.Requirement != RequirementApproval {
		t.Fatalf("unknown members: %+v, %v", parsed, err)
	}
	for _, bad := range []string{
		"",
		`resource-token="x"`,        // no requirement member
		`requirement="auth-token"`,  // a String, not a Token
		`requirement=(agent-token)`, // an inner list
		`requirement=auth-token; resource-token=?1`, // a Boolean parameter
		`requirement=auth-token; resource-token="unterminated`,
	} {
		if _, err := ParseRequirement(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestChallengeHelpers(t *testing.T) {
	cases := []struct {
		write func(http.ResponseWriter)
		want  string
	}{
		{ChallengeAgentToken, RequirementAgentToken},
		{ChallengePersonToken, RequirementPersonToken},
		{func(w http.ResponseWriter) { ChallengeAuthToken(w, "eyJ.e30.sig") }, RequirementAuthToken},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		c.write(rec)
		r, err := ParseRequirement(rec.Header().Get(HeaderRequirement))
		if rec.Code != http.StatusUnauthorized || err != nil || r.Requirement != c.want {
			t.Errorf("%s: status %d requirement %+v (%v)", c.want, rec.Code, r, err)
		}
	}
	rec := httptest.NewRecorder()
	WriteApprovalPending(rec, "/pending/abc", 30)
	r, err := ParseRequirement(rec.Header().Get(HeaderRequirement))
	if rec.Code != http.StatusAccepted || err != nil || r.Requirement != RequirementApproval ||
		rec.Header().Get(HeaderLocation) != "/pending/abc" || rec.Header().Get(HeaderRetryAfter) != "30" {
		t.Fatalf("approval: %d %v %+v (%v)", rec.Code, rec.Header(), r, err)
	}
}

func TestApprovalPendingIsFollowed(t *testing.T) {
	// requirement=approval (§11.6.4): the agent polls until terminal and
	// surfaces the requirement; no user action is needed on its side.
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && polls.Add(1) > 1 {
			writeBody(t, rw, "approved")
			return
		}
		WriteApprovalPending(rw, "/pending/abc", 0)
	}))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/act", nil)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	res, err := DoDeferred(context.Background(), srv.Client(), req, DeferredOptions{
		OnRequirement: func(r Requirement) { seen = append(seen, r.Requirement) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(res.Body)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "approved" || len(seen) != 1 || seen[0] != RequirementApproval {
		t.Fatalf("status %d body %q requirements %v", res.StatusCode, body, seen)
	}
}

func TestEffectiveAccessMode(t *testing.T) {
	for declared, want := range map[string]string{
		"":                     AccessModeAgentToken,
		AccessModeAgentToken:   AccessModeAgentToken,
		AccessModePersonToken:  AccessModePersonToken,
		AccessModeSessionToken: AccessModeSessionToken,
		AccessModeAuthToken:    AccessModeAuthToken,
		"aauth-access-token":   AccessModeAgentToken, // the pre-draft-11 name is not recognized
		"per-call":             AccessModeAgentToken, // an extension this implementation does not know
	} {
		if got := (ResourceMetadata{AccessMode: declared}).EffectiveAccessMode(); got != want {
			t.Errorf("%q: got %q, want %q", declared, got, want)
		}
	}
}

// threePartyWorld wires a full PS authorization deployment (draft -11
// §4.2.4): a PS that issues person tokens and, after verifying the agent,
// the resource token, and the presented person token, auth tokens; and a
// resource that challenges an agent token for a person token, a person
// token for an auth token, and serves on the auth token.
type threePartyWorld struct {
	agent            *Agent
	psAgent          *Agent // the PS's signing identity (keys only)
	psURL            string
	resourceKey      *Agent // the resource's signing identity (keys only)
	resourceURL      string
	interactionPolls int // >0: PS defers N polls before granting
	polls            atomic.Int32
	authTTL          time.Duration // auth token lifetime (default one hour)
	personRequests   atomic.Int32  // person token requests served
	authRequests     atomic.Int32  // auth token requests served
	agentResolver    KeyResolver   // resolves agent tokens at the resource (default self-signed)
	subagents        atomic.Int32  // requests that carried a subagent_token
}

// subagent verifies a subagent_token at the world's PS (§10.2.3): a
// self-hosted parent is its sub-agents' provider, so its key signs them.
func (w *threePartyWorld) subagent(r *http.Request, parent *AgentClaims, token string) (*AgentClaims, error) {
	if token == "" {
		return nil, nil
	}
	w.subagents.Add(1)
	return VerifySubagentToken(r.Context(), token, parent, VerifyAgentTokenOptions{
		Resolver: StaticResolver{parent.Issuer: {Keys: []JWK{*parent.Cnf.JWK}}},
	})
}

// resolver pins the PS's and the resource's keys.
func (w *threePartyWorld) resolver() StaticResolver {
	return StaticResolver{w.psURL: w.psAgent.JWKS(), w.resourceURL: w.resourceKey.JWKS()}
}

// personToken issues the agent a person token for resource, as the PS's
// person token endpoint would (§7.1).
func (w *threePartyWorld) personToken(t *testing.T, resource string) string {
	t.Helper()
	tok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: w.psURL, Resource: resource, Subject: "person-1", Agent: verifiedAgent(t, w.agent),
		InsecureSkipIdentifierCheck: true,
	}, w.psAgent.Key, w.psAgent.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// serveResource is the resource side of the world, for any resource URL
// whose key is w.resourceKey: it serves on an auth token, challenges a
// person token for an auth token, and an agent token for a person token.
// verified, when set, runs on each request whose person or auth token
// verified.
func (w *threePartyWorld) serveResource(t *testing.T, resourceURL func() string, scope string, verified func(*http.Request)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tok, err := ParseSignatureKey(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		typ, err := TokenType(tok)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		switch typ {
		case TypAuth:
			// §9.4.2: after authorization the agent presents the auth token.
			claims, err := VerifyAndExtractAuth(r.Context(), r, resourceURL(), AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(w.resolver())})
			if err != nil {
				WriteSignatureFailure(rw, err)
				return
			}
			if verified != nil {
				verified(r)
			}
			writeBody(t, rw, "hello %s scope=%s", claims.Subject, claims.Scope)
		case TypPerson:
			// §6.5: a verified person token, but consent is needed.
			person, err := VerifyAndExtractPerson(r.Context(), r, resourceURL(), localOpts(w.resolver()))
			if err != nil {
				WriteSignatureFailure(rw, err)
				return
			}
			if verified != nil {
				verified(r)
			}
			rt, err := IssueResourceToken(ResourceTokenParams{Resource: resourceURL(), Scope: scope}, person, w.resourceKey.Key, w.resourceKey.JWK().Kid)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			ChallengeAuthToken(rw, rt)
		default:
			// §6.4: the agent is known, the person is not.
			resolver := w.agentResolver
			if resolver == nil {
				resolver = SelfSignedResolver{}
			}
			if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: resolver}); err != nil {
				WriteSignatureFailure(rw, err)
				return
			}
			ChallengePersonToken(rw)
		}
	}
}

func newThreePartyWorld(t *testing.T) *threePartyWorld {
	t.Helper()
	w := &threePartyWorld{agent: testAgent(t)}
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	resID, _ := ParseAgentIdentifier("aauth:res@files.example")
	var err error
	if w.psAgent, err = NewAgent(psID); err != nil {
		t.Fatal(err)
	}
	if w.resourceKey, err = NewAgent(resID); err != nil {
		t.Fatal(err)
	}

	// --- Person Server ---
	psMux := http.NewServeMux()
	psMux.HandleFunc("POST /person", func(rw http.ResponseWriter, r *http.Request) {
		w.personRequests.Add(1)
		agent, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var preq PersonTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&preq); err != nil {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		sub, err := w.subagent(r, agent, preq.SubagentToken)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		tok, pc, err := IssuePersonToken(PersonTokenParams{
			Issuer: w.psURL, Resource: preq.Resource, Subject: "person-1", Agent: agent, Subagent: sub,
			MissionS256: preq.MissionS256, InsecureSkipIdentifierCheck: true,
		}, w.psAgent.Key, w.psAgent.JWK().Kid)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		writeJSON(t, rw, PersonTokenResponse{PersonToken: tok, ExpiresIn: int64(time.Until(pc.ExpiresAt.Time).Seconds())})
	})
	psMux.HandleFunc("POST /token", func(rw http.ResponseWriter, r *http.Request) {
		w.authRequests.Add(1)
		agent, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var treq AuthTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&treq); err != nil {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		// §6.7.2: the resource token is addressed to us and bound to this
		// agent's key, and the presented person token is ours, for that
		// resource, and the one the resource token names.
		sub, err := w.subagent(r, agent, treq.SubagentToken)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		bound := agent // §10.2.3: the resource token binds the sub-agent's key
		if sub != nil {
			bound = sub
		}
		rc, presented, err := VerifyResourceToken(r.Context(), treq.ResourceToken, ResourceTokenVerifyOptions{
			TokenVerifyOptions: localOpts(w.resolver()),
			Audience:           w.psURL,
			PS:                 w.psURL,
			AgentJKT:           bound.Cnf.JWK.Thumbprint(),
			PresentedToken:     treq.PresentedToken,
		})
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		if w.interactionPolls > 0 && int(w.polls.Load()) < w.interactionPolls {
			// User consent pending: defer with an interaction requirement.
			rw.Header().Set(HeaderLocation, "/pending/tok1")
			rw.Header().Set(HeaderRetryAfter, "0")
			rw.Header().Set(HeaderRequirement, Requirement{
				Requirement: RequirementInteraction,
				URL:         w.psURL + "/interaction",
				Code:        "A1B2-C3D4",
			}.String())
			rw.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(rw).Encode(PendingStatus{Status: "pending"})
			return
		}
		// §9.4.1: sub, account, mission_s256, and tenant from the
		// resource token; exp bounded by the agent and presented tokens.
		tok, _, err := IssueAuthToken(AuthTokenParams{
			Issuer: w.psURL, Resource: rc, Presented: presented, Agent: agent, Subagent: sub, Scope: rc.Scope, TTL: w.authTTL,
		}, w.psAgent.Key, w.psAgent.JWK().Kid)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		ac, err := VerifyAuthToken(r.Context(), tok, rc.Issuer, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(w.resolver())})
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		writeJSON(t, rw, AuthTokenResponse{AuthToken: tok, ExpiresIn: int64(time.Until(ac.ExpiresAt.Time).Seconds())})
	})
	psMux.HandleFunc("GET /pending/tok1", func(rw http.ResponseWriter, r *http.Request) {
		if int(w.polls.Add(1)) < w.interactionPolls {
			rw.Header().Set(HeaderLocation, "/pending/tok1")
			rw.Header().Set(HeaderRetryAfter, "0")
			rw.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(rw).Encode(PendingStatus{Status: "interacting"})
			return
		}
		// Consent arrived. (Poll GETs are unsigned in this test; the original
		// POST established identity — re-derive the grant from stored state.
		// Here we cheat and re-issue for the known test agent.)
		jwk := w.agent.JWK()
		w.writeAuthToken(t, rw, &AgentClaims{
			Cnf:              Cnf{JWK: &jwk},
			RegisteredClaims: jwt.RegisteredClaims{Subject: w.agent.ID.String()},
		}, &ResourceClaims{
			Scope:            "files:read",
			RegisteredClaims: jwt.RegisteredClaims{Issuer: w.resourceURL, Subject: "person-1"},
		})
	})
	ps := httptest.NewServer(psMux)
	t.Cleanup(ps.Close)
	w.psURL = ps.URL

	// --- Resource ---
	resMux := http.NewServeMux()
	resMux.HandleFunc("GET /files", w.serveResource(t, func() string { return w.resourceURL }, "files:read", nil))
	res := httptest.NewServer(resMux)
	t.Cleanup(res.Close)
	w.resourceURL = res.URL
	return w
}

func (w *threePartyWorld) writeAuthToken(t *testing.T, rw http.ResponseWriter, agent *AgentClaims, rc *ResourceClaims) {
	now := time.Now()
	jti, _ := randomJTI()
	tok, err := MintAuthToken(AuthClaims{
		DWK:   WellKnownPerson,
		PS:    w.psURL,
		Scope: rc.Scope,
		Cnf:   Cnf{JWK: agent.Cnf.JWK},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    w.psURL,
			Subject:   rc.Subject,
			Audience:  jwt.ClaimStrings{rc.Issuer},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}, w.psAgent.Key, w.psAgent.JWK().Kid)
	if err != nil {
		t.Errorf("mint auth token: %v", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(AuthTokenResponse{AuthToken: tok, ExpiresIn: 3600})
}

// callResource makes a signed GET to the resource with the given token.
func callResource(t *testing.T, a *Agent, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/files", nil)
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, token)
	if err := SignRequest(req, a.Key, a.Thumbprint()); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// challengeFor presents the agent's person token to the world's resource
// and returns the auth-token challenge (§6.5).
func (w *threePartyWorld) challengeFor(t *testing.T, personTok string) Requirement {
	t.Helper()
	res := callResource(t, w.agent, w.resourceURL, personTok)
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 challenge, got %d", res.StatusCode)
	}
	reqmt, err := ParseRequirement(res.Header.Get(HeaderRequirement))
	if err != nil || reqmt.Requirement != RequirementAuthToken || reqmt.ResourceToken == "" {
		t.Fatalf("challenge: %+v, %v", reqmt, err)
	}
	return reqmt
}

func TestThreePartyFlow(t *testing.T) {
	w := newThreePartyWorld(t)
	ctx := context.Background()

	// 1. The agent token alone: the resource needs the person (§6.4).
	agentTok, _ := w.agent.MintToken()
	res := callResource(t, w.agent, w.resourceURL, agentTok)
	closeBody(res.Body)
	if r, err := ParseRequirement(res.Header.Get(HeaderRequirement)); res.StatusCode != http.StatusUnauthorized || err != nil || r.Requirement != RequirementPersonToken {
		t.Fatalf("agent token: status %d requirement %+v (%v)", res.StatusCode, r, err)
	}

	// 2. With a person token: 401 auth-token challenge (§6.5).
	personTok := w.personToken(t, w.resourceURL)
	reqmt := w.challengeFor(t, personTok)

	// 3. The agent verifies the challenge (§6.7.3) before trusting it.
	rc, err := VerifyResourceChallenge(ctx, reqmt.ResourceToken, ResourceChallengeOptions{
		TokenVerifyOptions: localOpts(w.resolver()),
		Resource:           w.resourceURL,
		Agent:              w.agent,
		PS:                 w.psURL,
		Presented:          personTok,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Scope != "files:read" || rc.PS != w.psURL || rc.Subject != "person-1" {
		t.Fatalf("resource token claims %+v", rc)
	}

	// 4. Exchange at the PS token endpoint, with the person token as
	// presented_token (§7.2.1).
	psc := NewPSClient(w.psURL, w.agent)
	grant, err := psc.RequestAuthToken(ctx, AuthTokenRequest{
		ResourceToken:     reqmt.ResourceToken,
		PresentedToken:    personTok,
		TokenRequestHints: TokenRequestHints{Justification: "user asked to list project files"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Retry the resource with the auth token → 200.
	res2 := callResource(t, w.agent, w.resourceURL, grant.AuthToken)
	defer closeBody(res2.Body)
	body, _ := io.ReadAll(res2.Body)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("want 200 with auth token, got %d: %s", res2.StatusCode, body)
	}
	if want := "hello person-1 scope=files:read"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestThreePartyFlow_PresentedTokenChecks(t *testing.T) {
	w := newThreePartyWorld(t)
	ctx := context.Background()
	personTok := w.personToken(t, w.resourceURL)
	reqmt := w.challengeFor(t, personTok)
	psc := NewPSClient(w.psURL, w.agent)

	wantCode := func(name string, err error, code string) {
		t.Helper()
		var te *TokenError
		if !errors.As(err, &te) || te.Code != code {
			t.Errorf("%s: err = %v, want %s", name, err, code)
		}
	}
	// No presented_token: refused before it is sent (§7.2.1).
	_, err := psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: reqmt.ResourceToken})
	if !errors.Is(err, ErrPresentedTokenMissing) {
		t.Errorf("missing presented_token: err = %v", err)
	}
	// A different (valid) person token than the one the resource token
	// names: presented_jti mismatch.
	other := w.personToken(t, w.resourceURL)
	_, err = psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: reqmt.ResourceToken, PresentedToken: other})
	wantCode("other person token", err, TokenErrInvalidResourceToken)
	// A person token for another resource fails verification itself.
	elsewhere := w.personToken(t, "https://elsewhere.example")
	_, err = psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: reqmt.ResourceToken, PresentedToken: elsewhere})
	wantCode("person token for another resource", err, TokenErrInvalidPresentedToken)
	// An agent token is neither a person nor an auth token.
	agentTok, _ := w.agent.MintToken()
	_, err = psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: reqmt.ResourceToken, PresentedToken: agentTok})
	wantCode("agent token presented", err, TokenErrInvalidPresentedToken)
	// A resource token signed by an untrusted key.
	rogue := testAgent(t)
	pc, err := VerifyPersonToken(ctx, personTok, w.resourceURL, localOpts(w.resolver()))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := IssueResourceToken(ResourceTokenParams{Resource: w.resourceURL, Scope: "files:admin"}, pc, rogue.Key, rogue.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: forged, PresentedToken: personTok})
	wantCode("forged resource token", err, TokenErrInvalidResourceToken)
	// The agent-side check refuses it too (§6.7.3 step 2).
	if _, err := VerifyResourceChallenge(ctx, forged, ResourceChallengeOptions{
		TokenVerifyOptions: localOpts(w.resolver()), Resource: w.resourceURL, Agent: w.agent, PS: w.psURL, Presented: personTok,
	}); err == nil {
		t.Error("agent accepted a forged challenge")
	}
}

func TestThreePartyFlow_InteractionDeferred(t *testing.T) {
	w := newThreePartyWorld(t)
	w.interactionPolls = 2
	personTok := w.personToken(t, w.resourceURL)
	reqmt := w.challengeFor(t, personTok)

	var surfaced []Requirement
	psc := NewPSClient(w.psURL, w.agent)
	psc.OnRequirement = func(r Requirement) { surfaced = append(surfaced, r) }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grant, err := psc.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: reqmt.ResourceToken, PresentedToken: personTok})
	if err != nil {
		t.Fatal(err)
	}
	if grant.AuthToken == "" {
		t.Fatal("no auth token after interaction")
	}
	if len(surfaced) != 1 || surfaced[0].Requirement != RequirementInteraction || surfaced[0].Code != "A1B2-C3D4" {
		t.Fatalf("surfaced requirements: %+v", surfaced)
	}
}

func TestSubAgentCannotExchange(t *testing.T) {
	w := newThreePartyWorld(t)
	subID, _ := w.agent.ID.SubAgent("worker")
	sub := &Agent{ID: subID, Key: w.agent.Key, TokenTTL: time.Hour}
	psc := NewPSClient(w.psURL, sub)
	if _, err := psc.RequestAuthToken(context.Background(), AuthTokenRequest{ResourceToken: "x"}); err != ErrSubAgentDirect {
		t.Fatalf("err = %v, want ErrSubAgentDirect", err)
	}
}

// localOpts verifies server-issued tokens from local httptest servers,
// whose http://127.0.0.1:port URLs are not server identifiers.
func localOpts(r KeyResolver) TokenVerifyOptions {
	return TokenVerifyOptions{Resolver: r, InsecureSkipIdentifierCheck: true}
}
