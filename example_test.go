package aauth_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	aauth "github.com/aauth-dev/aauth-go"
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
// orchestrating agent (draft -11 §10.2).
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

// Example_resource is a resource using PS authorization (three-party): it
// answers an agent token with requirement=person-token, a verified person
// token with a resource token challenge (requirement=auth-token), and
// serves a request presenting a verified auth token.
func Example_resource() {
	const self = "https://files.example" // the resource's server identifier
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		log.Fatal(err)
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		log.Fatal(err)
	}
	// Person and auth token keys are discovered from each issuer's JWKS.
	// Token issuers are URLs the request chooses, so a nil client uses
	// aauth.DiscoveryClient, which reaches only public https destinations.
	verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(nil)}

	// A valid signature proves the issuer signed the claims, not that the
	// subject may use this resource. The resource keeps its own record of
	// the people it serves, keyed by (iss, sub): sub is unique only within
	// its issuer, so records from different issuers never match
	// (§9.4.3.2). This one enrolls people on first use, but only from the
	// person and access servers it has chosen to trust.
	trusted := map[string]bool{"https://ps.example": true, "https://as.example": true}
	var mu sync.Mutex
	people := map[[2]string]bool{}
	checkSubject := func(_ context.Context, iss, sub string) error {
		if !trusted[iss] {
			return fmt.Errorf("%w: %s is not an issuer this resource accepts", aauth.ErrInvalidToken, iss)
		}
		mu.Lock()
		defer mu.Unlock()
		people[[2]string{iss, sub}] = true
		return nil
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		tok, err := aauth.ParseSignatureKey(r)
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		typ, err := aauth.TokenType(tok)
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		switch typ {
		case aauth.TypAuth:
			claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, self, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: verify, CheckSubject: checkSubject})
			if err != nil {
				aauth.WriteSignatureFailure(w, err)
				return
			}
			if _, err := fmt.Fprintf(w, "hello %s (%s)", claims.Subject, claims.Scope); err != nil {
				log.Printf("write response: %v", err)
			}
		case aauth.TypPerson:
			person, err := aauth.VerifyAndExtractPerson(r.Context(), r, self, verify)
			if err != nil {
				aauth.WriteSignatureFailure(w, err)
				return
			}
			// The resource token's aud defaults to the person's PS.
			rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: self, Scope: "files:read"}, person, key, jwk.Kid)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aauth.ChallengeAuthToken(w, rt)
		default:
			aauth.ChallengePersonToken(w)
		}
	}
	http.HandleFunc("/files", handler)
}
