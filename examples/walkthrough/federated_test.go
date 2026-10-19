package walkthrough_test

import (
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// TestFederatedAuthorization runs four-party access: the resource chose
// an access server, so its resource tokens name the AS. The agent's code
// is the same as in PS authorization; the PS federates the request to
// the AS (federated-authorization.federate.ps), whose policy decides
// (federated-authorization.federate.as), and the auth token comes from
// the AS.
func TestFederatedAuthorization(t *testing.T) {
	w := newWorld(t)
	res := newDocumentsResource(t, w, w.asURL) // four-party: the AS decides
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	got := authorizeAndCall(t, w, agent, psc, res)
	if !strings.Contains(got, "plan.md") {
		t.Fatalf("API response %s", got)
	}
}

// TestFederatedAuthTokenIssuer checks that the auth token in four-party
// access is the access server's.
func TestFederatedAuthTokenIssuer(t *testing.T) {
	w := newWorld(t)
	res := newDocumentsResource(t, w, w.asURL)
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	pt := personToken(t, w, psc, res.url)
	tr := aauth.NewTransport(agent, psc)
	tr.ResourceVerify, tr.AuthVerify, tr.Base = w.verify, w.verify, w.hc.Transport
	tr.Capabilities = []string{aauth.CapabilityInteraction}
	result, err := tr.Authorize(w.ctx, res.url, aauth.AuthorizeRequest{Scope: "documents:read"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(w.ctx, result.AuthToken, res.url, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: w.verify})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != w.asURL {
		t.Fatalf("auth token iss %s, want the access server %s", claims.Issuer, w.asURL)
	}
	if pt == "" {
		t.Fatal("no person token")
	}
}
