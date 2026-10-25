package walkthrough_test

import (
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// personAPI is a resource that needs to know which person the agent acts
// for, and accepts any person server it trusts to say so.
type personAPI struct {
	url     string
	trusted map[string]bool
	verify  aauth.TokenVerifyOptions
}

func (p *personAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// pidl:begin person-identity.request.resource
	// The person token is addressed to this resource and bound to the
	// key that signed the request.
	person, err := aauth.VerifyAndExtractPerson(r.Context(), r, p.url, p.verify)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	// sub is unique within its PS only: key the person's record by both.
	if !p.trusted[person.Issuer] {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeInvalidRequest, "person server not accepted")
		return
	}
	respondJSON(w, map[string]string{"ps": person.Issuer, "person": person.Subject})
	// pidl:end person-identity.request.resource
}

func TestPersonIdentity(t *testing.T) {
	w := newWorld(t)
	api := &personAPI{trusted: map[string]bool{w.psURL: true}, verify: w.verify}
	api.url = serve(t, api)
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	ctx, hc, resURL := w.ctx, w.hc, api.url
	personToken := personToken(t, w, psc, resURL)

	// pidl:begin person-identity.request.agent
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resURL+"/api/documents", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Present the person token instead of the agent token: it names the
	// person and carries the agent's key, so the same signature works.
	aauth.AttachSignatureKey(req, personToken)
	if err := aauth.SignRequest(req, agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end person-identity.request.agent

	if got := readOK(t, res); !strings.Contains(got, w.psURL) {
		t.Fatalf("response %s", got)
	}
}
