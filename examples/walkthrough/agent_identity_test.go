package walkthrough_test

import (
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// agentAPI is a resource that decides on the agent's identity alone.
type agentAPI struct {
	resolver aauth.KeyResolver
}

func (a *agentAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// pidl:begin agent-identity.request.resource
	// The signature proves the request comes from the key in cnf.jwk of
	// the agent token; the token, signed by the agent provider, says
	// which agent holds that key.
	agent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{
		Resolver: a.resolver, // agent provider keys, discovered from the token's iss
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err) // 401 with Signature-Error
		return
	}
	// Decide on the agent: here, any agent from one provider's domain.
	if !strings.HasSuffix(agent.Subject, "@agent.example") {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeInvalidRequest, "unknown agent")
		return
	}
	respondJSON(w, map[string]string{"agent": agent.Subject, "documents": "plan.md, notes.md"})
	// pidl:end agent-identity.request.resource
}

func TestAgentIdentity(t *testing.T) {
	w := newWorld(t)
	resURL := serve(t, &agentAPI{resolver: aauth.NewJWKSResolver(w.hc)})
	agent := enrollAgent(t, w)
	ctx, hc := w.ctx, w.hc

	// pidl:begin agent-identity.request.agent
	token, err := agent.MintToken() // the current agent token, renewed before it expires
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resURL+"/api/documents", nil)
	if err != nil {
		t.Fatal(err)
	}
	aauth.AttachSignatureKey(req, token) // Signature-Key: sig=jwt;jwt="..."
	if err := aauth.SignRequest(req, agent.Key, ""); err != nil {
		t.Fatal(err) // Signature-Input and Signature over method, authority, path and Signature-Key
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end agent-identity.request.agent

	if got := readOK(t, res); !strings.Contains(got, agent.ID.String()) {
		t.Fatalf("response %s", got)
	}
}
