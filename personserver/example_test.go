package personserver_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
			switch {
			case r.Person == "":
				return personserver.DeferInteraction(), nil // a new agent: the person signs in at /consent
			case r.Chained && r.Mission == nil:
				// Call chaining (Config.AllowCallChaining) acts for the
				// person behind another agent's token: ask them.
				return personserver.DeferApproval(), nil
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
	mux.HandleFunc("GET /consent", func(w http.ResponseWriter, r *http.Request) {
		// Show the request; looking the code up does not consume it.
		p, err := ps.LookupCode(r.Context(), r.URL.Query().Get("code"), r.RemoteAddr)
		if err != nil {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		// Render the request and a form posting the code and p.Revision
		// back (sanitize the agent-asserted hints, §13.3).
		if _, err := fmt.Fprintf(w, "%s asks for %q at %s (revision %d)\n", p.Agent, p.Scope, p.Resource, p.Revision); err != nil {
			log.Print(err)
		}
	})
	mux.HandleFunc("POST /consent", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the person with the application's own login, then
		// consume the code as that person and approve the revision shown;
		// approval binds the agent to that person.
		person := "alice"
		p, err := ps.ConsumeCode(r.Context(), r.FormValue("code"), r.RemoteAddr, person)
		if err != nil {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		revision, err := strconv.Atoi(r.FormValue("revision"))
		if err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if err := ps.Approve(r.Context(), p.ID, personserver.Grant{Person: person, Revision: revision}); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
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
