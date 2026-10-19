# Resource

A resource verifies whichever token a request presents and challenges for the
next one. With PS authorization (three-party), an agent token is answered
with `requirement=person-token`, a person token with a resource token
challenge (`requirement=auth-token`), and an auth token is served:

```go
const self = "https://files.example" // the resource's server identifier
verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(nil)} // nil: aauth.DiscoveryClient

// A valid signature proves the issuer signed the claims, not that this
// resource should trust that issuer or its subjects. Token issuers are URLs
// the request chooses, so accept only the person and access servers you have
// chosen to trust, and key your own records by (iss, sub): sub is unique only
// within its issuer (§9.4.3.2).
trusted := map[string]bool{"https://ps.example": true, "https://as.example": true}
checkSubject := func(ctx context.Context, iss, sub string) error {
	if !trusted[iss] {
		return fmt.Errorf("%w: %s is not an issuer this resource accepts", aauth.ErrInvalidToken, iss)
	}
	return nil // or look up (iss, sub) in your own records
}

handler := func(w http.ResponseWriter, r *http.Request) {
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil {
		aauth.WriteSignatureFailure(w, err) // 401 with Signature-Error
		return
	}
	typ, err := aauth.TokenType(tok)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	switch typ {
	case aauth.TypAuth:
		claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, self,
			aauth.AuthTokenVerifyOptions{TokenVerifyOptions: verify, CheckSubject: checkSubject})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		// The identity is (iss, sub), never sub alone. The granted scope is
		// the issuer's claim: apply your own policy to it before acting.
		serve(w, claims.Issuer, claims.Subject, claims.Scope)
	case aauth.TypPerson:
		person, err := aauth.VerifyAndExtractPerson(r.Context(), r, self, verify)
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		rt, err := aauth.IssueResourceToken(
			aauth.ResourceTokenParams{Resource: self, Scope: "files:read"},
			person, resourceKey, resourceKID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aauth.ChallengeAuthToken(w, rt) // 401 requirement=auth-token
	default:
		aauth.ChallengePersonToken(w) // 401 requirement=person-token
	}
}
```

In four-party mode, also restrict which access server may grant which scopes
(draft -11 §13.7). The resource also serves `/.well-known/aauth-resource.json`
(`aauth.ResourceMetadata`) and the JWKS holding `resourceKey`. A resource that
needs only the agent's identity stops at `aauth.VerifyAndExtractAgent`. For
four-party access, set `ResourceTokenParams.Audience` to the resource's
access server. The compile-checked version is
[`Example_resource`](https://pkg.go.dev/github.com/aauth-dev/aauth-go#example-package-Resource).

## Protect Operations with ResourceGuard

Most resources need different levels for different operations: reading a
catalog needs only the agent's identity, an order needs the person, and a
change needs the person's consent for a scope. `aauth.ResourceGuard` writes
the switch above once. Each operation declares the least it requires, and the
guard verifies the presented token, answers with the next requirement when
it falls short, and passes the verified caller to the handler:

```go
guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
	Resource:    self,                      // aud of the tokens it accepts
	Key:         resourceKey,               // signs resource tokens
	Verify:      verify,                    // PS and AS keys
	TrustIssuer: aauth.TrustIssuers("https://ps.example"),
	Metadata:    aauth.ResourceMetadata{AccessMode: aauth.AccessModeAuthToken},
})
if err != nil {
	return err
}
mux := http.NewServeMux()
mux.Handle("GET /pets", guard.Require(aauth.Access{Level: aauth.AccessAgent}, listPets))
mux.Handle("POST /orders", guard.Require(aauth.Access{Level: aauth.AccessPerson}, placeOrder))
mux.Handle("DELETE /pets/{id}", guard.Require(aauth.Access{Level: aauth.AccessAuth, Scope: "pets:write"}, deletePet))
mux.Handle("/", guard.WellKnown()) // metadata and keys
```

In a handler, `aauth.CallerFromContext` returns who called: the token type,
the agent's key thumbprint (and identifier, from an agent token), the
person's `(Issuer, Subject)`, and the granted scope.

| The operation requires | and the request presents | The guard answers |
|---|---|---|
| any level | no `Signature-Key` | 401 `requirement=agent-token` |
| `AccessPerson` or `AccessAuth` | an agent token | 401 `requirement=person-token` |
| `AccessAuth` | a person token | 401 `requirement=auth-token` with a resource token for the scope |
| `AccessAuth` | an auth token without the scope | 401 `requirement=auth-token` for the token's scope plus the new one |
| any level | a token from an issuer `TrustIssuer` refuses | 403 |

An agent using `aauth.Transport` answers each challenge itself. The
challenge for a missing scope also asks for the scope the agent already
holds, because the agent keeps one auth token per resource: the new token
replaces the old one without losing access.
