package personserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// Why the PS could not use the access server stays in its log: the agent
// sees as_unreachable with a generic detail.
func TestASUnreachableDetailIsGeneric(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	f.script = func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		return nil, errors.New("dial tcp 10.1.2.3:8443: connection refused")
	}
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	_, err := w.psClient(w.agent).RequestAuthToken(context.Background(), aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if tokenCode(err) != aauth.TokenErrASUnreachable || strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("err %v", err)
	}
}

// The PS polls the access server no faster than its Retry-After, even
// while an agent's poll is held for Prefer: wait.
func TestFederationPollHonorsRetryAfter(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	f.script = func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		return &FederationResponse{PendingURL: testAS + "/pending/1", Requirement: aauth.Requirement{Requirement: aauth.RequirementApproval}, RetryAfter: 30}, nil
	}
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	res := w.signed(w.agent, "", http.MethodPost, w.ps.paths.AuthToken, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	loc := res.Header.Get(aauth.HeaderLocation)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, w.psURL+loc, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(aauth.HeaderPrefer, "wait=2")
	tok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	aauth.AttachSignatureKey(req, tok)
	if err := aauth.SignRequest(req, w.agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if res.StatusCode != http.StatusAccepted || calls != 1 {
		t.Fatalf("status %d, %d calls to the access server", res.StatusCode, calls)
	}
}
