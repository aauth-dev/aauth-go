package personserver

import (
	"context"
	"errors"
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
