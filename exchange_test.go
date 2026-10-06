package aauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if _, err := ParseRequirement("resource-token=\"x\""); err == nil {
		t.Fatal("missing requirement param accepted")
	}
}

// threePartyWorld wires a full PS-Asserted deployment: a PS that issues auth
// tokens after verifying agent + resource token, and a resource that
// challenges unknown callers and trusts the PS's key.
type threePartyWorld struct {
	agent            *Agent
	psAgent          *Agent // the PS's signing identity (keys only)
	psURL            string
	resourceKey      *Agent // the resource's signing identity (keys only)
	resourceURL      string
	interactionPolls int // >0: PS defers N polls before granting
	polls            atomic.Int32
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
	psMux.HandleFunc("POST /token", func(rw http.ResponseWriter, r *http.Request) {
		agent, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		var treq TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&treq); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		// Verify the resource token: addressed to us, bound to this agent,
		// signed by the resource (trust pinned).
		rc, err := VerifyResourceToken(r.Context(), treq.ResourceToken, w.psURL, agent,
			localOpts(StaticResolver{w.resourceURL: w.resourceKey.JWKS()}))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
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
		w.writeAuthToken(t, rw, agent, rc)
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
			RegisteredClaims: jwt.RegisteredClaims{Issuer: w.resourceURL},
		})
	})
	ps := httptest.NewServer(psMux)
	t.Cleanup(ps.Close)
	w.psURL = ps.URL

	// --- Resource ---
	resMux := http.NewServeMux()
	resMux.HandleFunc("GET /files", func(rw http.ResponseWriter, r *http.Request) {
		// Try auth token first (§9.4.2: after authorization the agent
		// presents the auth token, not the agent token).
		if tok, err := ParseSignatureKey(r); err == nil {
			if strings.Contains(headerTyp(tok), TypAuth) {
				claims, err := VerifyAndExtractAuth(r.Context(), r, w.resourceURL,
					localOpts(StaticResolver{w.psURL: w.psAgent.JWKS()}))
				if err != nil {
					http.Error(rw, err.Error(), http.StatusForbidden)
					return
				}
				writeBody(t, rw, "hello %s scope=%s", claims.Agent, claims.Scope)
				return
			}
		}
		// Otherwise authenticate the agent and challenge for an auth token.
		agent, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		rt, err := IssueResourceToken(w.resourceURL, w.psURL, agent, "files:read", w.resourceKey.Key, w.resourceKey.JWK().Kid)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		ChallengeAuthToken(rw, rt)
	})
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
		Agent: agent.Subject,
		Scope: rc.Scope,
		Cnf:   Cnf{JWK: agent.Cnf.JWK},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    w.psURL,
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
	_ = json.NewEncoder(rw).Encode(TokenResponse{AuthToken: tok, ExpiresIn: 3600})
}

func headerTyp(token string) string {
	parts := strings.SplitN(token, ".", 2)
	h, err := jwt.NewParser().DecodeSegment(parts[0])
	if err != nil {
		return ""
	}
	return string(h)
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

func TestThreePartyFlow(t *testing.T) {
	w := newThreePartyWorld(t)
	ctx := context.Background()

	// 1. Agent calls the resource with its agent token → 401 challenge.
	agentTok, _ := w.agent.MintToken()
	res := callResource(t, w.agent, w.resourceURL, agentTok)
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 challenge, got %d", res.StatusCode)
	}
	reqmt, err := ParseRequirement(res.Header.Get(HeaderRequirement))
	if err != nil || reqmt.Requirement != RequirementAuthToken || reqmt.ResourceToken == "" {
		t.Fatalf("challenge: %+v, %v", reqmt, err)
	}

	// 2. Agent verifies the challenge (§6.7.3) before trusting it.
	rc, err := VerifyResourceChallenge(reqmt.ResourceToken, w.resourceURL, w.agent)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Scope != "files:read" {
		t.Fatalf("scope = %q", rc.Scope)
	}

	// 3. Exchange at the PS token endpoint.
	psc := NewPSClient(w.psURL, w.agent)
	grant, err := psc.ExchangeToken(ctx, TokenRequest{
		ResourceToken: reqmt.ResourceToken,
		Justification: "user asked to list project files",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 4. Retry the resource with the auth token → 200.
	res2 := callResource(t, w.agent, w.resourceURL, grant.AuthToken)
	defer closeBody(res2.Body)
	body, _ := io.ReadAll(res2.Body)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("want 200 with auth token, got %d: %s", res2.StatusCode, body)
	}
	if want := "hello " + w.agent.ID.String() + " scope=files:read"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestThreePartyFlow_InteractionDeferred(t *testing.T) {
	w := newThreePartyWorld(t)
	w.interactionPolls = 2

	agentTok, _ := w.agent.MintToken()
	res := callResource(t, w.agent, w.resourceURL, agentTok)
	closeBody(res.Body)
	reqmt, _ := ParseRequirement(res.Header.Get(HeaderRequirement))

	var surfaced []Requirement
	psc := NewPSClient(w.psURL, w.agent)
	psc.OnRequirement = func(r Requirement) { surfaced = append(surfaced, r) }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grant, err := psc.ExchangeToken(ctx, TokenRequest{ResourceToken: reqmt.ResourceToken})
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
	if _, err := psc.ExchangeToken(context.Background(), TokenRequest{ResourceToken: "x"}); err != ErrSubAgentDirect {
		t.Fatalf("err = %v, want ErrSubAgentDirect", err)
	}
}

// localOpts verifies server-issued tokens from local httptest servers,
// whose http://127.0.0.1:port URLs are not server identifiers.
func localOpts(r KeyResolver) TokenVerifyOptions {
	return TokenVerifyOptions{Resolver: r, InsecureSkipIdentifierCheck: true}
}
