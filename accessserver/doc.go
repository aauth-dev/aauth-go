// Package accessserver implements the Access Server role of AAuth
// (draft-hardt-oauth-aauth-protocol-11 §9) and the PS side of PS-AS
// federation.
//
// A [Server] is an http.Handler serving the AS token endpoint (§9.1), its
// pending URLs, its revocation endpoint (§11.12), the metadata document
// aauth-access.json, and its JWKS. The PS signs every request under the
// jwks_uri scheme; the AS verifies the agent token, any sub-agent token,
// the resource token addressed to it together with the presented token it
// names (re-verified here, §9.1.1), and any upstream token, then asks the
// caller's [Authorizer] — the library never decides resource policy. A
// decision allows (an auth token with dwk aauth-access.json), denies,
// requires identity claims (§9.2), or defers to an interaction,
// approval, or clarification that the hosting application resolves with
// [Server.Approve], [Server.Deny], or [Server.Ask].
//
// [Client] is a personserver.Federator that makes PS-to-AS requests over
// HTTP. [Server.Local] is an in-process Federator for PS-AS collapse
// (§9.3.3), when one deployment hosts both roles:
//
//	as, _ := accessserver.New(accessserver.Config{
//		Issuer: "https://example.com", Key: asKey, Store: asStore,
//		Authorizer: accessserver.AuthorizerFunc(func(ctx context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
//			return accessserver.Allow(""), nil // the resource token's scope
//		}),
//	})
//	ps, _ := personserver.New(personserver.Config{
//		Issuer: "https://example.com", Key: psKey, ..., Federator: as.Local("https://example.com"),
//	})
//	mux := http.NewServeMux()
//	ps.Register(mux) // /ps/..., /.well-known/aauth-person.json
//	as.Register(mux) // /as/..., /.well-known/aauth-access.json
//
// Each role keeps its own key, metadata document, and JWKS, so tokens and
// signatures stay distinguishable by dwk even on one origin.
package accessserver
