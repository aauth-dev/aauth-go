package walkthrough_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
)

// enrollments is the agent provider's Registrar: it decides which agent a
// presented key is, from the provider's own enrollment fields.
type enrollments struct {
	ps string // the person server agents work with
}

// AuthorizeIssue authorizes an hwk-signed issuance request.
func (e enrollments) AuthorizeIssue(_ context.Context, _ *http.Request, req *agentprovider.IssueRequest) (*agentprovider.Registration, error) {
	// pidl:begin agent-token.attest.ap
	var body struct {
		Device string `json:"device"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil || body.Device == "" {
		return nil, errors.New("enrollment names the device")
	}
	// A stable local part per install (bootstrap §6), and the person
	// server this agent works with, carried as the ps claim.
	return &agentprovider.Registration{Name: "assistant-" + body.Device, PS: e.ps}, nil
	// pidl:end agent-token.attest.ap
}

// AuthorizeRefresh is not used in the walkthrough.
func (enrollments) AuthorizeRefresh(context.Context, *agentprovider.RefreshRequest) (*agentprovider.Registration, error) {
	return nil, errors.New("refresh is not enrolled")
}

// AuthorizeSubagent is not used in the walkthrough.
func (enrollments) AuthorizeSubagent(context.Context, *agentprovider.SubagentRequest) (*agentprovider.SubagentGrant, error) {
	return nil, errors.New("sub-agents are not enrolled")
}

// newAgentProvider configures the hosted agent provider.
func newAgentProvider(t *testing.T, issuer, ps string, hc *http.Client) *agentprovider.Server {
	t.Helper()
	// pidl:begin agent-token.agent-token.ap
	// The provider signs agent tokens with its own key, never an agent's.
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := agentprovider.New(agentprovider.Config{
		Issuer:     issuer,
		Domain:     "agent.example", // agent identifiers are aauth:<name>@agent.example
		Key:        key,
		Registrar:  enrollments{ps: ps}, // decides which agent each key is
		HTTPClient: hc,
	})
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end agent-token.agent-token.ap
	return ap
}

// enrollAgent runs the agent-token fragment: the agent creates its key,
// enrolls it with the provider, and checks the agent token it receives.
func enrollAgent(t *testing.T, w *world) *aauth.Agent {
	t.Helper()
	ctx, hc, apURL := w.ctx, w.hc, w.apURL

	// pidl:begin agent-token.attest.agent
	key, err := aauth.GenerateKey(aauth.AlgEd25519) // or a key held in a platform keystore
	if err != nil {
		t.Fatal(err)
	}
	apc := &agentprovider.Client{BaseURL: apURL, HTTPClient: hc}
	enrollment := map[string]string{"device": "laptop-42"}
	// Issue signs the request with the new key under the hwk scheme.
	issued, err := apc.Issue(ctx, key, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end agent-token.attest.agent

	agent := agentFromToken(t, w, apc, key, issued, enrollment)
	if agent.ID.Name != "assistant-laptop-42" {
		t.Fatalf("agent = %s", agent.ID)
	}
	return agent
}

// agentFromToken checks a freshly issued agent token and builds the agent.
func agentFromToken(t *testing.T, w *world, apc *agentprovider.Client, key crypto.Signer, issued *agentprovider.TokenResponse, enrollment any) *aauth.Agent {
	t.Helper()
	ctx, hc := w.ctx, w.hc

	// pidl:begin agent-token.agent-token.agent
	claims, err := aauth.VerifyAgentToken(ctx, issued.AgentToken, aauth.VerifyAgentTokenOptions{
		Resolver: aauth.NewJWKSResolver(hc), // the provider's keys, from its metadata
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := aauth.ParseAgentIdentifier(claims.Subject)
	if err != nil {
		t.Fatal(err)
	}
	// The agent signs with its own key and presents tokens from the
	// provider, renewed before they expire.
	agent, err := aauth.NewAgent(id, aauth.WithKey(key), aauth.WithPersonServer(claims.PS),
		aauth.WithTokenSource(apc.TokenSource(func(ctx context.Context) (*agentprovider.TokenResponse, error) {
			return apc.Issue(ctx, key, enrollment)
		})))
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end agent-token.agent-token.agent
	return agent
}

func TestAgentToken(t *testing.T) {
	w := newWorld(t)
	agent := enrollAgent(t, w)
	token, err := agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(w.ctx, token, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(w.hc)})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != w.apURL || claims.PS != w.psURL {
		t.Fatalf("iss %s ps %s", claims.Issuer, claims.PS)
	}
}
