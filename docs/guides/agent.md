# Agent

A self-hosted agent is its own agent provider (bootstrap §4.3): it holds a
key, mints its own agent tokens, and serves `/.well-known/aauth-agent.json`
and its JWKS (`Agent.JWKS`) at its issuer. Wrap an `http.Client` with
`Transport` and AAuth disappears from application code:

```go
id, err := aauth.ParseAgentIdentifier("aauth:assistant@agent.example")
if err != nil {
	return err
}
agent, err := aauth.NewAgent(id,
	aauth.WithIssuer("https://agent.example"),    // serves aauth-agent.json and the JWKS
	aauth.WithPersonServer("https://ps.example"), // the ps claim
)
if err != nil {
	return err
}

ps := aauth.NewPSClient("https://ps.example", agent)
if _, err := ps.Discover(ctx); err != nil { // endpoints from aauth-person.json
	return err
}

hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
res, err := hc.Get("https://files.example/files")
```

For each request the transport signs with the agent's key and answers
`requirement=agent-token`, `person-token`, and `auth-token` challenges (401,
or a 202 deferred delivery): it obtains a person token, redeems the resource
token at the PS, verifies what it receives, caches tokens per resource with a
five-minute refresh margin, and retries. Set `Transport.OnRequirement` to
show the user an interaction URL and code while a request waits for them.

An agent whose tokens come from a hosted provider uses
`aauth.WithTokenSource`, for example with `agentprovider.Client.TokenSource`.

Governance is optional and uses the same client:

```go
m, err := ps.ProposeMission(ctx, aauth.MissionProposal{
	Description: "Reconcile the March invoices",
	Resources:   []string{"https://ledger.example"},
})
if err != nil {
	return err
}
tr := aauth.NewTransport(agent, ps)
tr.MissionS256 = m.S256 // person and auth tokens are requested under the mission

perm, err := ps.RequestPermission(ctx, aauth.PermissionRequest{
	Action:      "SendEmail",
	Description: "email the reconciliation summary",
	MissionS256: m.S256,
})
if err != nil {
	return err // a *aauth.MissionStatusError once the mission is terminated
}
if !perm.Granted() {
	return errors.New(perm.Reason)
}
```
