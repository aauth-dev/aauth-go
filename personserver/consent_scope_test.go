package personserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// While the PS follows the access server after consenting, an
// updated_request answering the AS's clarification may not widen the
// scope the person consented to (the default Grant consents to the
// resource token's scope); a narrower one is relayed and delivered.
func TestFederatedUpdatedRequestKeepsConsentedScope(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{}) })
	f.script = func(_ int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		f.mu.Lock()
		var post *aauth.ClarificationPost
		if len(f.answers) > 0 {
			post, _ = f.answers[len(f.answers)-1].(*aauth.ClarificationPost)
		}
		if post != nil && post.ResourceToken != "" {
			f.last.ResourceToken, f.last.PresentedToken = post.ResourceToken, post.PresentedToken
		}
		f.mu.Unlock()
		if post == nil {
			return &FederationResponse{PendingURL: testAS + "/pending/1",
				Requirement: aauth.Requirement{Requirement: aauth.RequirementClarification}, Question: &Question{Text: "Which folder?"}}, nil
		}
		return grant(mint, nil), nil
	}
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read files:write", Audience: testAS})
	res := w.signed(w.agent, "", http.MethodPost, w.ps.paths.AuthToken, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	loc := res.Header.Get(aauth.HeaderLocation)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", res.StatusCode)
	}
	id := strings.TrimPrefix(loc, w.ps.paths.Pending)
	p, err := w.ps.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if p.Federation == nil || p.Federation.GrantedScope != "files:read files:write" {
		t.Fatalf("federation %+v", p.Federation)
	}

	// Broader: refused, and nothing is relayed to the AS.
	wide := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read files:write files:admin", Audience: testAS})
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionUpdatedRequest, ResourceToken: wide, PresentedToken: pt})
	if code := errorCode(t, res); res.StatusCode != http.StatusBadRequest || code != aauth.TokenErrInvalidResourceToken {
		t.Fatalf("broader update: %d %s", res.StatusCode, code)
	}
	f.mu.Lock()
	relayed := len(f.answers)
	f.mu.Unlock()
	if relayed != 0 {
		t.Fatalf("relayed %d answers", relayed)
	}

	// Another AS: refused (aud is pinned).
	elsewhere := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: "https://as.other.example"})
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionUpdatedRequest, ResourceToken: elsewhere, PresentedToken: pt})
	if code := errorCode(t, res); res.StatusCode != http.StatusBadRequest || code != aauth.TokenErrInvalidResourceToken {
		t.Fatalf("other aud: %d %s", res.StatusCode, code)
	}

	// Narrower: relayed, and the AS's token is delivered.
	narrow := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	res = w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionUpdatedRequest, ResourceToken: narrow, PresentedToken: pt})
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("narrower update: %d", res.StatusCode)
	}
	res = w.signed(w.agent, "", http.MethodGet, loc, nil)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var tr aauth.AuthTokenResponse
	if err := json.Unmarshal(b, &tr); err != nil || tr.AuthToken == "" {
		t.Fatalf("poll: %d %s", res.StatusCode, b)
	}
	var ac aauth.AuthClaims
	if err := parseUnverified(tr.AuthToken, &ac); err != nil {
		t.Fatal(err)
	}
	if ac.Scope != "files:read" {
		t.Fatalf("delivered scope %q", ac.Scope)
	}
}

// A delivered AS token broader than the consented scope is refused even
// when the request's resource token would allow it.
func TestFederatedDeliveryWithinConsent(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{Scope: "files:read"}) })
	f.script = func(_ int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		return grant(mint, nil), nil // the resource token's full scope
	}
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read files:write", Audience: testAS})
	_, err := w.psClient(w.agent).RequestAuthToken(context.Background(), aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if tokenCode(err) != aauth.TokenErrASUnreachable {
		t.Fatalf("err %v", err)
	}
}
