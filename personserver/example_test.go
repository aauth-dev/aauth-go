package personserver_test

import (
	"context"
	"crypto/rand"
	"log"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
	"github.com/aauth-dev/aauth-go/ratelimit"
)

// Example_collapsedDeployment hosts an agent provider, a person server,
// and an access server on one origin (draft -11 §4.3, §9.3.3). Storage and
// policy are the hosting application's: the in-memory stores and limiters
// here are for a single instance only, and the Decider and Authorizer
// stand in for real consent and access policy.
func Example_collapsedDeployment() {
	const issuer = "https://example.com" // shared by the collocated roles
	ctx := context.Background()

	// Each role has its own signing key, metadata document, and JWKS.
	apKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		log.Fatal(err)
	}
	psKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		log.Fatal(err)
	}
	asKey, err := aauth.GenerateKey(aauth.AlgES256)
	if err != nil {
		log.Fatal(err)
	}
	subjectKey := make([]byte, 32) // keep stable: it derives directed sub values
	if _, err := rand.Read(subjectKey); err != nil {
		log.Fatal(err)
	}

	ap, err := agentprovider.New(agentprovider.Config{
		Issuer:  issuer,
		Key:     apKey,
		Limiter: ratelimit.Per(10, time.Minute),
	})
	if err != nil {
		log.Fatal(err)
	}

	as, err := accessserver.New(accessserver.Config{
		Issuer: issuer,
		Key:    asKey,
		Store:  accessserver.NewMemoryStore(), // implement accessserver.Store over your database
		Authorizer: accessserver.AuthorizerFunc(func(ctx context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Allow(""), nil // the resource token's scope
		}),
		Limiter: ratelimit.Per(5, time.Second),
	})
	if err != nil {
		log.Fatal(err)
	}

	var ps *personserver.Server
	ps, err = personserver.New(personserver.Config{
		Issuer:         issuer,
		Key:            psKey,
		SubjectKey:     subjectKey,
		Store:          personserver.NewMemoryStore(), // implement personserver.Store over your database
		InteractionURL: issuer + "/consent",
		Decider: personserver.DeciderFunc(func(ctx context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			if r.Person == "" {
				return personserver.DeferInteraction(), nil // a new agent: the person signs in at /consent
			}
			return personserver.Allow(personserver.Grant{}), nil
		}),
		// Resources governed by the collocated access server are federated
		// in process rather than over HTTP.
		Federator:    as.Local(issuer),
		CollocatedAS: func(resource string) bool { return resource == "https://ledger.example" },
		Limiter:      ratelimit.Per(5, time.Second),
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	ap.Register(mux)
	ps.Register(mux)
	as.Register(mux)
	mux.HandleFunc("/consent", func(w http.ResponseWriter, r *http.Request) {
		p, err := ps.ConsumeCode(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		// Authenticate the person with the application's own login, then
		// approve; approval binds the agent to that person.
		if err := ps.Approve(r.Context(), p.ID, personserver.Grant{Person: "alice"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// The application issues agent tokens for keys it has authorized, for
	// example a key bound to one of its work sessions.
	agentKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		log.Fatal(err)
	}
	jwk, err := aauth.NewJWK(agentKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	if _, _, err := ap.IssueAgentToken(ctx, agentprovider.AgentTokenParams{Name: "session-7", Key: jwk, PS: issuer}); err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	_ = srv // srv.ListenAndServeTLS(certFile, keyFile)
}
