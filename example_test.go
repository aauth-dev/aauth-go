package aauth_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	aauth "github.com/aauth-dev/auth-go"
)

// Example shows the two ends of the cooperative permission flow: an agent
// asks a Person Server before acting, and the server authenticates the agent.
func Example() {
	// Agent side: mint an identity and ask before acting.
	id, _ := aauth.ParseAgentIdentifier("aauth:claude-code@devbox.local")
	agent, _ := aauth.NewAgent(id, aauth.WithPersonServer("http://127.0.0.1:7421"))

	ps := aauth.NewPSClient("http://127.0.0.1:7421", agent)
	_, err := ps.RequestPermission(context.Background(), aauth.PermissionRequest{
		Action:      "WriteFile",
		Description: "write the deploy config",
		Parameters:  map[string]any{"path": "/tmp/deploy.yaml"},
	})
	_ = err // res.Granted() reports the decision; a 202 is followed automatically.

	// Server side: authenticate the agent behind an endpoint.
	_ = func(w http.ResponseWriter, r *http.Request) {
		claims, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{
			Resolver: aauth.SelfSignedResolver{},
		})
		if err != nil {
			// 401 with the matching Signature-Error code.
			aauth.WriteSignatureFailure(w, err)
			return
		}
		if _, err := fmt.Fprintf(w, "authenticated %s", claims.Subject); err != nil {
			log.Printf("write response: %v", err)
		}
	}
}

// ExampleTransport wraps an http.Client so AAuth is transparent: signing,
// 401 challenges, token exchange, and caching all happen automatically.
func ExampleTransport() {
	id, _ := aauth.ParseAgentIdentifier("aauth:assistant@agent.example")
	agent, _ := aauth.NewAgent(id)
	ps := aauth.NewPSClient("https://ps.example", agent)

	hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
	// This call signs itself, and if the resource answers 401 with an
	// auth-token challenge, the transport exchanges a token and retries.
	res, err := hc.Get("https://files.example/files")
	if err != nil {
		log.Printf("request failed: %v", err)
		return
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("close body: %v", err)
		}
	}()
}

// ExampleAgentIdentifier_SubAgent derives a short-lived worker under an
// orchestrating agent (draft -09 §10.2).
func ExampleAgentIdentifier_SubAgent() {
	parent, _ := aauth.ParseAgentIdentifier("aauth:orchestrator@example.com")
	worker, _ := parent.SubAgent("search-1")
	fmt.Println(worker)
	fmt.Println(worker.IsSubAgent())
	// Output:
	// aauth:orchestrator+search-1@example.com
	// true
}

// ExampleParseAgentIdentifier parses an agent identifier into its parts.
func ExampleParseAgentIdentifier() {
	id, _ := aauth.ParseAgentIdentifier("aauth:claude-code@devbox.local")
	fmt.Println(id.Name, id.Domain, id.IsSubAgent())
	// Output:
	// claude-code devbox.local false
}

// ExampleNewAgent_es256 creates an agent with a P-256 key (ES256), the
// usual choice where keys live in a secure enclave. Any crypto.Signer with
// a P-256 or Ed25519 public key can be supplied with WithKey instead.
func ExampleNewAgent_es256() {
	id, _ := aauth.ParseAgentIdentifier("aauth:assistant@agent.example")
	agent, err := aauth.NewAgent(id, aauth.WithKeyAlgorithm(aauth.AlgES256))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(agent.JWK().Alg)
	// Output: ES256
}
