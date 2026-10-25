package walkthrough_test

import (
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// decidePersonToken is the person server's decision on a person token
// request.
func decidePersonToken(r *personserver.TokenRequest) personserver.Decision {
	// pidl:begin person-token.request.ps
	// The person token says which person the agent acts for. This PS
	// enrolled the agent from alice's signed-in session, so an agent it
	// has not bound yet is bound to her; a bound agent keeps its person.
	if r.Person == "" {
		return personserver.Allow(personserver.Grant{Person: "alice"})
	}
	return personserver.Allow(personserver.Grant{})
	// pidl:end person-token.request.ps
}

// personToken runs the person-token fragment for resourceURL.
func personToken(t *testing.T, w *world, psc *aauth.PSClient, resourceURL string) string {
	t.Helper()
	ctx := w.ctx

	// pidl:begin person-token.request.agent
	// A person token is issued for one resource: it becomes the token's
	// aud. The client signs the request with the agent token and caches
	// the result until shortly before it expires.
	personToken, err := psc.PersonToken(ctx, aauth.PersonTokenRequest{Resource: resourceURL})
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end person-token.request.agent
	return personToken
}

func TestPersonToken(t *testing.T) {
	w := newWorld(t)
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	const resource = "https://resource.example"
	tok := personToken(t, w, psc, resource)
	claims, err := aauth.VerifyPersonToken(w.ctx, tok, resource, w.verify)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != w.psURL || claims.Subject == "" {
		t.Fatalf("person token iss %s sub %q", claims.Issuer, claims.Subject)
	}
	if again := personToken(t, w, psc, resource); again != tok {
		t.Error("person token was not cached")
	}
}
