// Package personserver implements the Person Server role of AAuth
// (draft-hardt-oauth-aauth-protocol-11 §7): the person token endpoint, the
// auth token endpoint, deferred (pending) requests with clarification
// chat, and the metadata document and JWKS a PS publishes.
//
// The package is library-first and storage-agnostic. A [Server] is an
// http.Handler configured with:
//
//   - a [Store] holding agent-person bindings, directed identifiers, token
//     records for revocation, missions, and pending requests
//     ([NewMemoryStore] is a reference implementation for tests);
//   - a [Decider] that makes every consent decision. The library never
//     decides policy: a decision allows, denies, or defers, and a deferred
//     request is resolved later by the hosting application through
//     [Server.Approve], [Server.Deny], [Server.Fail], or [Server.Ask] — from
//     its own approval UI, a push notification, or an administrator queue.
//
// The PS authenticates every agent request by its HTTP message signature
// and agent token (§11.3), derives a pairwise directed identifier per
// resource with a keyed HMAC ([DirectedSubject]), binds each agent to
// exactly one person (§13.14), records the tokens it issues for revocation
// (§11.12.4), and verifies resource tokens together with the presented
// token they name (§6.7.2), call-chaining upstream tokens (§9.4.5), and
// sub-agent tokens (§10.2).
//
// One origin can host a PS, an agent provider, and an access server: each
// role has its own key, metadata document, and JWKS, and [Server.Register]
// adds the PS routes (under /ps/ by default) to a shared mux.
//
// A minimal deployment:
//
//	ps, err := personserver.New(personserver.Config{
//		Issuer:         "https://ps.example",
//		Key:            psKey,
//		SubjectKey:     subjectKey, // 32+ random bytes, kept stable
//		Store:          store,
//		InteractionURL: "https://ps.example/consent",
//		Decider: personserver.DeciderFunc(func(ctx context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
//			if r.Person == "" {
//				return personserver.DeferInteraction(), nil // enroll a new agent
//			}
//			return personserver.Allow(personserver.Grant{}), nil
//		}),
//	})
//	http.Handle("/", ps)
//
// The consent page reads ?code=, calls [Server.ConsumeCode], authenticates
// the person (§13.13), and calls [Server.Approve] with the person's
// identifier, which binds the agent.
package personserver
