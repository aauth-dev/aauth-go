# Resource

A resource verifies whichever token a request presents and challenges for the
next one. With PS authorization (three-party), an agent token is answered
with `requirement=person-token`, a person token with a resource token
challenge (`requirement=auth-token`), and an auth token is served:

```go
const self = "https://files.example" // the resource's server identifier
verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(nil)} // nil: aauth.DiscoveryClient

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
			aauth.AuthTokenVerifyOptions{TokenVerifyOptions: verify})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		serve(w, claims.Subject, claims.Scope) // directed sub, granted scope
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

The resource also serves `/.well-known/aauth-resource.json`
(`aauth.ResourceMetadata`) and the JWKS holding `resourceKey`. A resource that
needs only the agent's identity stops at `aauth.VerifyAndExtractAgent`. For
four-party access, set `ResourceTokenParams.Audience` to the resource's
access server. The compile-checked version is
[`Example_resource`](https://pkg.go.dev/github.com/aauth-dev/aauth-go#example-package-Resource).
