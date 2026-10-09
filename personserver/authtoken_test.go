package personserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// get performs a GET through the agent transport and returns the body.
func get(t *testing.T, tr *aauth.Transport, url string) string {
	t.Helper()
	res, err := (&http.Client{Transport: tr}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, b)
	}
	return string(b)
}

func TestThreePartyFlow(t *testing.T) {
	w := newWorld(t, nil)
	var seen []*TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = append(seen, r)
		if r.Kind == KindAuthToken {
			return Allow(Grant{Scope: "files:read"})
		}
		return Allow(Grant{Person: "alice"})
	})
	w.scope = "files:read files:write"
	tr := w.transport(w.agent, w.psClient(w.agent))
	body := get(t, tr, w.resURL+"/files")
	sub := DirectedSubject(w.ps.cfg.SubjectKey, "alice", w.resURL)
	if body != "hello "+sub+" scope=files:read" {
		t.Fatalf("body %q", body)
	}
	if len(seen) != 2 || seen[1].Kind != KindAuthToken || seen[1].Scope != "files:read files:write" || seen[1].Person != "alice" {
		t.Fatalf("decisions %+v", seen)
	}
	// The issued auth token is recorded against its person token.
	_, auths, err := w.store.TokensForAgent(context.Background(), agentRefOf(w.agent))
	if err != nil || len(auths) != 1 || auths[0].PersonJTI == "" || auths[0].Issuer != w.psURL {
		t.Fatalf("records %+v %v", auths, err)
	}
	// A grant broader than the request is a programming error.
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{Scope: "admin"}) })
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("broader scope: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestAuthTokenRequestErrors(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	other := w.otherAgent("other")
	otherPT := w.personToken(other, w.resURL, "")
	foreignRT := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "x", Audience: "https://as.example"})

	for name, c := range map[string]struct {
		body any
		want string
	}{
		"no resource token":  {aauth.AuthTokenRequest{PresentedToken: pt}, aauth.TokenErrInvalidRequest},
		"no presented token": {aauth.AuthTokenRequest{ResourceToken: rt}, aauth.TokenErrInvalidRequest},
		"garbage":            {aauth.AuthTokenRequest{ResourceToken: "x.y.z", PresentedToken: pt}, aauth.TokenErrInvalidResourceToken},
		"wrong presented":    {aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: otherPT}, aauth.TokenErrInvalidPresentedToken},
		"not federating":     {aauth.AuthTokenRequest{ResourceToken: foreignRT, PresentedToken: pt}, aauth.TokenErrInvalidResourceToken},
	} {
		res := w.signed(w.agent, "", http.MethodPost, "/ps/token", c.body)
		if got := errorCode(t, res); got != c.want {
			t.Errorf("%s: status %d error %q, want %q", name, res.StatusCode, got, c.want)
		}
	}
	// Another agent presenting this agent's person token and a resource
	// token bound to its own key is refused.
	otherRT := w.resourceToken(otherPT, aauth.ResourceTokenParams{Scope: "files:read"})
	if err := w.store.Unbind(ctx, agentRefOf(other)); err != nil {
		t.Fatal(err)
	}
	res := w.signed(other, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: otherRT, PresentedToken: otherPT})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedPresentedToken {
		t.Errorf("unbound agent: %q", got)
	}
	// A resource token its resource withdrew, and a person token the PS
	// revoked (§11.12.4).
	rc := claimsOf(t, rt)
	if err := w.store.Revoke(ctx, rc.Issuer, rc.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res = w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedResourceToken {
		t.Errorf("revoked resource token: %q", got)
	}
	rt2 := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	pc := personClaimsOf(t, pt)
	if err := w.store.Revoke(ctx, pc.Issuer, pc.ID, pc.ExpiresAt.Time); err != nil {
		t.Fatal(err)
	}
	res = w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt2, PresentedToken: pt})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedPresentedToken {
		t.Errorf("revoked presented token: %q", got)
	}
}

func claimsOf(t *testing.T, rt string) *aauth.ResourceClaims {
	t.Helper()
	var c aauth.ResourceClaims
	if err := parseUnverified(rt, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func personClaimsOf(t *testing.T, tok string) *aauth.PersonClaims {
	t.Helper()
	var c aauth.PersonClaims
	if err := parseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestAuthTokenClarificationAndUpdate(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.personToken(w.agent, w.resURL, "") // bind
	w.setDecide(func(r *TokenRequest) Decision {
		if r.Kind == KindAuthToken {
			return DeferClarification("Why write access?", "read only", "read and write")
		}
		return Allow(Grant{})
	})
	w.scope = "files:read files:write"
	c := w.psClient(w.agent)
	var asked []string
	c.OnClarification = func(q aauth.Clarification) (aauth.ClarificationReply, error) {
		asked = append(asked, q.Question)
		if len(asked) == 1 {
			return aauth.ClarificationReply{Text: "to save your edits"}, nil
		}
		// Second round: replace the request with a narrower one.
		pt := w.personToken(w.agent, w.resURL, "")
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
		return aauth.ClarificationReply{ResourceToken: rt, PresentedToken: pt, Justification: "read only then"}, nil
	}
	w.setNotify(func(p *Pending) {
		if !p.Open() || p.Question != nil {
			return
		}
		go func() {
			switch len(p.Transcript) {
			case 1:
				if err := w.ps.Ask(ctx, p.ID, Question{Text: "Still need write?"}); err != nil {
					t.Error(err)
				}
			case 2:
				if p.Scope != "files:read" || !p.Transcript[1].Updated || p.Hints.Justification != "read only then" {
					t.Errorf("updated request not applied: %+v", p)
				}
				if err := w.ps.Approve(ctx, p.ID, Grant{}); err != nil {
					t.Error(err)
				}
			}
		}()
	})
	tr := w.transport(w.agent, c)
	body := get(t, tr, w.resURL+"/files")
	if !strings.HasSuffix(body, "scope=files:read") || len(asked) != 2 {
		t.Fatalf("body %q, questions %v", body, asked)
	}
}

func TestClarificationLimitsAndCancel(t *testing.T) {
	w := newWorld(t, func(c *Config) { c.MaxClarificationRounds = 2 })
	ctx := context.Background()
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	// Open a pending request directly and drive its pending URL.
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", res.StatusCode)
	}
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	id := strings.TrimPrefix(loc, "/ps/pending/")
	if err := w.ps.Ask(ctx, id, Question{}); err == nil {
		t.Fatal("empty question accepted")
	}
	if err := w.ps.Ask(ctx, id, Question{Text: "one?"}); err != nil {
		t.Fatal(err)
	}
	if err := w.ps.Ask(ctx, id, Question{Text: "again?"}); !errors.Is(err, ErrQuestionPending) {
		t.Fatalf("second outstanding question: %v", err)
	}
	// A POST without an action, and an updated_request for a person token.
	res = w.signed(w.agent, "", http.MethodPost, loc, map[string]string{"clarification_response": "x"})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("no action: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionUpdatedRequest, ResourceToken: "a", PresentedToken: "b"})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("updated_request on a person token: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionClarificationResponse, ClarificationResponse: "because"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("answer: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionClarificationResponse, ClarificationResponse: "again"})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unasked answer: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	if err := w.ps.Ask(ctx, id, Question{Text: "two?"}); err != nil {
		t.Fatal(err)
	}
	if err := w.ps.Ask(ctx, id, Question{Text: "three?"}); !errors.Is(err, ErrQuestionPending) {
		t.Fatalf("outstanding: %v", err)
	}
	p, err := w.ps.PendingRequest(ctx, id)
	if err != nil || p.Rounds != 2 || len(p.Transcript) != 1 || p.Transcript[0].Answer != "because" {
		t.Fatalf("pending %+v %v", p, err)
	}
	// The poll shows the clarification.
	res = w.signed(w.agent, "", http.MethodGet, loc, nil)
	req, _ := aauth.ParseRequirement(res.Header.Get(aauth.HeaderRequirement))
	if res.StatusCode != http.StatusAccepted || req.Requirement != aauth.RequirementClarification {
		t.Fatalf("poll: %d %+v", res.StatusCode, req)
	}
	_ = res.Body.Close()
	// Another agent cannot see it.
	other := w.otherAgent("other")
	res = w.signed(other, "", http.MethodGet, loc, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("other agent: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	// The agent cancels; the pending URL is then gone.
	res = w.signed(w.agent, "", http.MethodDelete, loc, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodGet, loc, nil)
	if res.StatusCode != http.StatusGone {
		t.Fatalf("after cancel: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	if err := w.ps.Approve(ctx, id, Grant{Person: "alice"}); !errors.Is(err, ErrResolved) {
		t.Fatalf("approve after cancel: %v", err)
	}
	if err := w.ps.MarkInteracting(ctx, id); !errors.Is(err, ErrResolved) {
		t.Fatalf("interacting after cancel: %v", err)
	}
	res = w.signed(w.agent, "", http.MethodPut, "/ps/pending/nope", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown pending: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestRoundLimit(t *testing.T) {
	w := newWorld(t, func(c *Config) { c.MaxClarificationRounds = 1 })
	ctx := context.Background()
	w.setDecide(func(*TokenRequest) Decision { return DeferClarification("first?") })
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionClarificationResponse, ClarificationResponse: "ok"})
	_ = res.Body.Close()
	if err := w.ps.Ask(ctx, strings.TrimPrefix(loc, "/ps/pending/"), Question{Text: "second?"}); !errors.Is(err, ErrClarificationLimit) {
		t.Fatalf("limit: %v", err)
	}
}

func TestPendingExpiryAndRevocation(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	open := func() string {
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
		res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusAccepted {
			t.Fatalf("status %d", res.StatusCode)
		}
		return res.Header.Get(aauth.HeaderLocation)
	}
	// The resource withdraws the resource token while it waits.
	loc := open()
	p, err := w.ps.PendingRequest(ctx, strings.TrimPrefix(loc, "/ps/pending/"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.Revoke(ctx, p.ResourceTokenIssuer, p.ResourceTokenJTI, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res := w.signed(w.agent, "", http.MethodGet, loc, nil)
	if got := errorCode(t, res); res.StatusCode != http.StatusForbidden || got != aauth.PollErrRevoked {
		t.Fatalf("revoked dependency: %d %q", res.StatusCode, got)
	}
	// A request nobody decides times out.
	loc = open()
	w.advance(11 * time.Minute)
	p, err = w.ps.PendingRequest(ctx, strings.TrimPrefix(loc, "/ps/pending/"))
	if err != nil || p.Result == nil || p.Result.Status != http.StatusRequestTimeout || p.Open() {
		t.Fatalf("expired: %+v %v", p, err)
	}
}

func TestApproveAfterTokenExpiry(t *testing.T) {
	// A presented token that expires while the person decides yields
	// expired at the pending URL rather than a token outliving it.
	w := newWorld(t, func(c *Config) { c.PersonTokenTTL = 2 * time.Minute; c.PendingTTL = time.Hour })
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	id := strings.TrimPrefix(loc, "/ps/pending/")
	w.advance(5 * time.Minute)
	if err := w.ps.Approve(ctx, id, Grant{}); err != nil {
		t.Fatal(err)
	}
	p, err := w.ps.PendingRequest(ctx, id)
	if err != nil || p.Result == nil || p.Result.Status != http.StatusRequestTimeout {
		t.Fatalf("pending %+v %v", p, err)
	}
}

func TestResourceInteraction(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read",
		Interaction: &aauth.ResourceInteraction{URL: "https://files.example/connect", Code: "WXYZ-1234"}})
	c := w.psClient(w.agent)
	w.setNotify(func(p *Pending) {
		if !p.Open() || p.CodeConsumed {
			return
		}
		go func() {
			if p.ResourceInteraction == nil || p.Requirement != aauth.RequirementInteraction {
				t.Errorf("pending %+v", p)
				return
			}
			if _, err := w.ps.ConsumeCode(ctx, p.Code); err != nil {
				t.Error(err)
				return
			}
			if err := w.ps.Approve(ctx, p.ID, Grant{}); err == nil {
				t.Error("approved before the resource's interaction")
			}
			u, err := ResourceInteractionURL(p, "https://ps.example/cb/1")
			if err != nil || u != "https://files.example/connect?code=WXYZ-1234&callback=https%3A%2F%2Fps.example%2Fcb%2F1" {
				t.Errorf("redirect %q %v", u, err)
			}
			if err := w.ps.CompleteResourceInteraction(ctx, p.ID, ""); err != nil {
				t.Error(err)
			}
			if err := w.ps.Approve(ctx, p.ID, Grant{}); err != nil {
				t.Error(err)
			}
		}()
	})
	tr, err := c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt,
		TokenRequestHints: aauth.TokenRequestHints{Capabilities: []string{"interaction"}}})
	if err != nil || tr.AuthToken == "" {
		t.Fatalf("%+v %v", tr, err)
	}
	// A callback error abandons the request with the mapped error.
	for cbErr, want := range map[string]string{"access_denied": aauth.PollErrDenied, "user_abandoned": aauth.PollErrAbandoned,
		"interaction_expired": aauth.PollErrExpired, "server_error": aauth.ErrCodeServerError} {
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read",
			Interaction: &aauth.ResourceInteraction{URL: "https://files.example/connect", Code: "WXYZ-1234"}})
		w.setNotify(func(p *Pending) {
			if p.Open() {
				go func() {
					if err := w.ps.CompleteResourceInteraction(ctx, p.ID, cbErr); err != nil {
						t.Error(err)
					}
				}()
			}
		})
		_, err := c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt,
			TokenRequestHints: aauth.TokenRequestHints{Capabilities: []string{"interaction"}}})
		if tokenCode(err) != want {
			t.Errorf("%s: %v", cbErr, err)
		}
	}
	if _, err := ResourceInteractionURL(&Pending{}, ""); err == nil {
		t.Error("no interaction accepted")
	}
	if _, err := ResourceInteractionURL(&Pending{ResourceInteraction: &aauth.ResourceInteraction{URL: "http://x.example"}}, ""); err == nil {
		t.Error("http interaction url accepted")
	}
}

func TestSubagentTokens(t *testing.T) {
	w := newWorld(t, nil)
	sub, err := w.agent.NewSubAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	var seen *TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = r
		return Allow(Grant{Person: "alice"})
	})
	// The sub-agent's transport uses its parent's PS client (§10.2.3).
	tr := w.transport(sub, w.psClient(w.agent))
	if body := get(t, tr, w.resURL+"/x"); !strings.HasPrefix(body, "hello ") {
		t.Fatalf("body %q", body)
	}
	if seen.Subagent == nil || seen.Subagent.Subject != sub.ID.String() || seen.Agent.Subject != w.agent.ID.String() {
		t.Fatalf("decider saw %+v", seen)
	}
	// A subagent_token that does not name the signing agent.
	other := w.otherAgent("other")
	subTok, err := sub.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := w.signed(other, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL, SubagentToken: subTok})
	if got := errorCode(t, res); got != aauth.TokenErrInvalidSubagentToken {
		t.Fatalf("foreign sub-agent: %q", got)
	}
	// A revoked sub-agent token.
	sc := agentClaimsOf(t, subTok)
	if err := w.store.Revoke(context.Background(), sc.Issuer, sc.ID, sc.ExpiresAt.Time); err != nil {
		t.Fatal(err)
	}
	res = w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL, SubagentToken: subTok})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedSubagentToken {
		t.Fatalf("revoked sub-agent: %q", got)
	}
}

func agentClaimsOf(t *testing.T, tok string) *aauth.AgentClaims {
	t.Helper()
	var c aauth.AgentClaims
	if err := parseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestCallChaining(t *testing.T) {
	// An intermediary r1 that is its own agent provider obtains a person
	// token and an auth token for the downstream resource for the same
	// person, with the upstream token as evidence (§10.1.1).
	w := newWorld(t, nil)
	ctx := context.Background()
	const r1 = "https://r1.example"
	upstream := w.personToken(w.agent, r1, "")
	inter := newAgent(t, "proxy", r1, "")
	w.pin(r1, inter.JWKS())
	var seen *TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = r
		return Allow(Grant{})
	})
	ic := w.psClient(inter)
	pr, err := ic.RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	if !seen.Chained || seen.Person != "alice" {
		t.Fatalf("decider saw %+v", seen)
	}
	down, err := aauth.VerifyPersonToken(ctx, pr.PersonToken, w.resURL, w.psOpts())
	if err != nil {
		t.Fatal(err)
	}
	up := personClaimsOf(t, upstream)
	if down.Subject == up.Subject || down.Subject != DirectedSubject(w.ps.cfg.SubjectKey, "alice", w.resURL) {
		t.Fatal("the downstream sub must be the person's directed identifier at the downstream resource")
	}
	if down.ExpiresAt.After(up.ExpiresAt.Time) {
		t.Fatal("the downstream token outlives the upstream token")
	}
	// The intermediary has no binding of its own.
	if _, err := w.store.BoundPerson(ctx, agentRefOf(inter)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("intermediary bound: %v", err)
	}
	rt := w.resourceToken(pr.PersonToken, aauth.ResourceTokenParams{Scope: "files:read"})
	at, err := ic.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pr.PersonToken, UpstreamToken: upstream})
	if err != nil || at.AuthToken == "" {
		t.Fatalf("%+v %v", at, err)
	}
	// An upstream token not addressed to the intermediary is refused.
	wrong := w.personToken(w.agent, w.resURL, "")
	_, err = ic.RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: wrong})
	if tokenCode(err) != aauth.TokenErrInvalidUpstreamToken {
		t.Fatalf("wrong aud: %v", err)
	}
	// Once the calling agent's binding is revoked, its upstream tokens are.
	if err := w.store.Unbind(ctx, agentRefOf(w.agent)); err != nil {
		t.Fatal(err)
	}
	_, err = ic.RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: upstream})
	if tokenCode(err) != aauth.TokenErrRevokedUpstreamToken {
		t.Fatalf("revoked binding: %v", err)
	}
}

// A second intermediary: caller → r1 → r2 → resource. r1 holds a person
// token for r2 that names r1 as its agent; the original caller's binding is
// what must be checked at the next hop, not r1's.
func TestCallChainingSecondHop(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	const r1, r2 = "https://r1.example", "https://r2.example"
	upstream := w.personToken(w.agent, r1, "")
	inter1 := newAgent(t, "proxy1", r1, "")
	inter2 := newAgent(t, "proxy2", r2, "")
	w.pin(r1, inter1.JWKS())
	w.pin(r2, inter2.JWKS())
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{}) })

	// r1 obtains a person token for r2 on the caller's upstream token.
	pr1, err := w.psClient(inter1).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: r2, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	// r2 chains on it toward the resource.
	pr2, err := w.psClient(inter2).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: pr1.PersonToken})
	if err != nil {
		t.Fatalf("second hop: %v", err)
	}
	if pr2.PersonToken == "" {
		t.Fatal("no person token for the second hop")
	}

	// Revoking a token in the middle of the chain stops the next hop.
	pc1 := personClaimsOf(t, pr1.PersonToken)
	if _, err := w.ps.RevokePersonToken(ctx, pc1.ID); err != nil {
		t.Fatal(err)
	}
	_, err = w.psClient(inter2).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: pr1.PersonToken})
	if tokenCode(err) != aauth.TokenErrRevokedUpstreamToken {
		t.Fatalf("revoked intermediate token: %v", err)
	}

	// And so does revoking the original caller's binding.
	pr1b, err := w.psClient(inter1).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: r2, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.Unbind(ctx, agentRefOf(w.agent)); err != nil {
		t.Fatal(err)
	}
	_, err = w.psClient(inter2).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: pr1b.PersonToken})
	if tokenCode(err) != aauth.TokenErrRevokedUpstreamToken {
		t.Fatalf("revoked origin binding: %v", err)
	}
}
