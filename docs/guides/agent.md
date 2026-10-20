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

## Get Tokens from a Hosted Agent Provider

An agent whose tokens come from a hosted provider enrolls its key there.
`agentprovider.Client.Enroll` issues the first agent token and returns an
`aauth.Agent` with the identifier, issuer and person server that token names;
new tokens are issued for the same key as the current one nears expiry:

```go
ap := &agentprovider.Client{BaseURL: "https://ap.example"}
agent, err := ap.Enroll(ctx, key, nil) // key: the agent's crypto.Signer
if err != nil {
	return err
}
ps := aauth.NewPSClient(agent.PS, agent)
hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
```

For other refresh schemes, such as the two-key refresh, pass
`agentprovider.Client.TokenSource` to `aauth.WithTokenSource`.

## Declare Capabilities

A resource or person server may ask the person to act (interaction), ask the
agent a question (clarification), or ask for payment only when the agent says
it can handle that (§11.7). Declare what your agent handles on the transport;
it is sent as `AAuth-Capabilities` on requests to resources and as the
`capabilities` parameter of person and auth token requests:

```go
tr := aauth.NewTransport(agent, ps)
tr.Capabilities = []string{aauth.CapabilityInteraction}
tr.OnRequirement = func(r aauth.Requirement) {
	if r.Requirement == aauth.RequirementInteraction {
		fmt.Printf("Approve at %s (code %s)\n", r.URL, r.Code)
	}
}
```

Without a declaration, recipients assume the agent can do none of these and
refuse rather than wait for a person who will never be asked.

## Request Access Ahead of a Call

A resource with an authorization endpoint (§6.6) can be asked for a scope
before the first call. `Transport.Authorize` presents a person token, follows
any wait for the person, and caches what it obtains, so the next request is
served directly:

```go
res, err := tr.Authorize(ctx, "https://files.example", aauth.AuthorizeRequest{Scope: "files:write"})
if err != nil {
	return err // a *aauth.ProblemError for invalid_scope or invalid_account
}
// res.AuthToken (a resource token redeemed at the PS), or res.Scope and
// res.SessionToken when the resource authorized the agent itself.
```

## Pay When a Resource Asks

A resource or access server answers 402 Payment Required when access costs
money (§6.5, §11.8.4). The SDK carries the payment protocol's challenge and
leaves settling it to you: set `Transport.Payment` and declare
`CapabilityPayment`, and the transport settles, then polls `Location` or
retries the request:

```go
tr.Capabilities = append(tr.Capabilities, aauth.CapabilityPayment)
tr.Payment = aauth.PaymentHandlerFunc(func(ctx context.Context, p *aauth.PaymentRequiredError) error {
	// p.Challenges (WWW-Authenticate) and p.Body name the payment protocol,
	// such as x402; pay through it, then return nil.
	return payWith(ctx, p)
})
```

Without a handler, a 402 is returned to the caller.

## Missions and Permissions

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
