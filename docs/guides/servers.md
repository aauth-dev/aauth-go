# Hosted AP, PS, and AS

The server roles are `http.Handler`s over interfaces you implement: storage
(`personserver.Store`, `accessserver.Store`) and policy
(`personserver.Decider`, `accessserver.Authorizer`, and the optional
`MissionApprover`, `PermissionDecider`, `InteractionRelay`, and
`agentprovider.Registrar`). The library never decides policy. A decision
allows, denies, or defers, and the hosting application resolves deferred
requests from its own approval UI (`Approve`, `Deny`, `Ask`).

One origin can host all three roles (PS-AS collapse, §9.3.3); each keeps its
own key, metadata document, and JWKS:

```go
ap, err := agentprovider.New(agentprovider.Config{
	Issuer: issuer, Key: apKey,
	Limiter: ratelimit.Per(10, time.Minute),
})

as, err := accessserver.New(accessserver.Config{
	Issuer: issuer, Key: asKey,
	Store: accessserver.NewMemoryStore(), // your database in production
	Authorizer: accessserver.AuthorizerFunc(func(ctx context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
		return accessserver.Allow(""), nil // the resource token's scope
	}),
	Limiter: ratelimit.Per(5, time.Second),
})

ps, err := personserver.New(personserver.Config{
	Issuer: issuer, Key: psKey,
	SubjectKey:     subjectKey, // 32+ random bytes, kept stable
	Store:          personserver.NewMemoryStore(),
	InteractionURL: issuer + "/consent",
	Decider: personserver.DeciderFunc(func(ctx context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
		if r.Person == "" {
			return personserver.DeferInteraction(), nil // a new agent: the person signs in at /consent
		}
		return personserver.Allow(personserver.Grant{}), nil
	}),
	Federator:    as.Local(issuer), // in-process PS-AS federation
	CollocatedAS: func(resource string) bool { return resource == "https://ledger.example" },
	Limiter:      ratelimit.Per(5, time.Second),
})

mux := http.NewServeMux()
ap.Register(mux)
ps.Register(mux)
as.Register(mux)
```

The consent page passes the `?code=` it receives to `ps.ConsumeCode`,
authenticates the person, and calls `ps.Approve` with a `Grant` naming the
person, which binds the agent. `ap.IssueAgentToken` issues tokens for agent
keys the application has authorized. The PS routes live under `/ps/` by
default, so agents find them with `PSClient.Discover`. The full,
compile-checked version is
[`Example_collapsedDeployment`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/personserver#example-package-CollapsedDeployment),
and the [`e2e`](https://github.com/aauth-dev/aauth-go/tree/main/e2e) test runs the whole flow: enrollment, three-party
access, missions, PS-AS collapse, audit, and a revocation cascade.
