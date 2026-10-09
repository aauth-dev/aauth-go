# Flows

Each flow below is a sequence diagram of the messages between roles. The
roles and tokens are introduced in [How AAuth works](how-aauth-works.md). Where
a step is a call you make, the diagram names the Go type. Where a role answers
on its own, the diagram shows the HTTP exchange.

The three-party, mission, and revocation flows follow the calls the library's
end-to-end scenario makes; run it with `AAUTH_E2E_TRACE=1` to see the same
sequence with real requests ([Testing](testing.md)). Section numbers refer to
draft -11, and [Protocol coverage](../specs/protocol-coverage.md) says what
the library implements of each.

In every diagram, each request from the agent is an HTTP message signature
made with the agent's own key. The token it carries rides in the
`Signature-Key` header.

## 1. Get an agent token

An agent token binds the agent's key to its identifier. How the agent gets one
depends on who runs its agent provider.

### Self-hosted

The agent is its own provider. It mints a token with its own key and serves
its metadata and JWKS so verifiers can check it. `Transport` mints a fresh
token for each request.

```mermaid
sequenceDiagram
    participant A as Agent (also its own AP)
    participant R as Resource

    A->>R: GET /files, signed, agent token
    R->>A: GET /.well-known/aauth-agent.json and JWKS
    R-->>A: metadata and keys
    R-->>A: 200 (identity verified)
```

### Hosted: enroll and refresh

A hosted provider issues tokens for keys the application authorizes. An agent
enrolls by signing a request with the new key (the `hwk` scheme) and your
`Registrar` decides whether to issue. A durable key can later delegate to a
fresh ephemeral key (the two-key refresh), so the long-lived key stays out of
everyday requests.

```mermaid
sequenceDiagram
    participant A as Agent
    participant AP as Hosted agent provider
    participant Reg as Registrar (your code)

    A->>AP: POST token, signed with the new key (hwk)
    AP->>Reg: AuthorizeIssue(key, body, attestation)
    Reg-->>AP: registration (or refusal)
    AP-->>A: agent token

    Note over A,AP: Later, two-key refresh
    A->>AP: POST refresh, naming JWT from the durable key, signed by an ephemeral key
    AP->>Reg: authorize the refresh
    Reg-->>AP: allowed
    AP-->>A: agent token bound to the ephemeral key
```

## 2. Identity only

A resource that needs only to know which agent is calling verifies the agent
token and serves. This is `VerifyAndExtractAgent`, and the shortest path
through the protocol.

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource

    A->>R: GET /files, signed, no token yet
    R-->>A: 401 AAuth-Requirement agent-token
    A->>R: GET /files, signed, agent token
    R-->>A: 200
```

## 3. Three-party access

The resource wants a person's authorization. This is the full exchange for a
first request to a new resource.

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource
    participant PS as Person Server

    A->>R: GET /files, agent token
    R-->>A: 401 requirement=person-token
    A->>PS: POST person token request
    PS-->>A: person token (directed sub for this resource)
    A->>R: GET /files, person token
    R-->>A: 401 requirement=auth-token, resource token
    A->>PS: POST auth token request, resource token and presented token
    PS-->>A: auth token
    A->>R: GET /files, auth token
    R-->>A: 200
```

Points worth knowing:

- The person token carries a **directed** identifier. The PS derives it per
  resource from a keyed HMAC, so two resources cannot tell they are talking
  about the same person.
- The resource token names the token the request presented, and the PS checks
  the two together. The agent cannot swap in a different person's token.
- The agent checks the resource token and the auth token it receives before
  using them. `Transport` does all of this and retries the original request.
- Tokens are cached per resource and replaced shortly before they expire (a
  five-minute margin), so later requests skip most of these steps.

## 4. A new agent: consent

The first time a PS sees an agent, it has no person bound to it. Your `Decider`
defers, and the request waits while the person approves. Any AAuth endpoint can
answer `202` this way.

```mermaid
sequenceDiagram
    participant A as Agent
    participant PS as Person Server
    participant D as Decider (your code)
    participant P as Person

    A->>PS: POST person token request
    PS->>D: Decide(request)
    D-->>PS: DeferInteraction
    PS-->>A: 202, Location, requirement=interaction (url, code)
    Note over A: Transport.OnRequirement shows the url and code
    A-)P: show the interaction URL and code
    P->>PS: open consent page with the code
    PS->>PS: ConsumeCode
    P->>PS: sign in and approve
    PS->>PS: Approve(person) binds the agent to the person
    A->>PS: GET Location (poll, honoring Retry-After)
    PS-->>A: 200 person token
```

Each interaction code is single use. The hosting application authenticates the
person and calls `Approve`, `Deny`, or `Fail`; the library never decides. A
PS may instead ask a clarifying question before deciding:

```mermaid
sequenceDiagram
    participant A as Agent
    participant PS as Person Server

    A->>PS: POST auth token request
    PS-->>A: 202, requirement=clarification, question
    A->>PS: POST clarification_response (or updated_request)
    PS-->>A: 202 (still pending)
    A->>PS: GET Location
    PS-->>A: 200 auth token
    Note over A,PS: The agent may also DELETE Location to withdraw the request
```

## 5. Four-party access

The resource's resource token names an Access Server as its audience. The agent
still talks only to its PS. The PS passes the request to the AS, which may
defer to the resource owner.

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource
    participant PS as Person Server
    participant AS as Access Server
    participant O as Resource owner

    A->>R: GET /ledger, person token
    R-->>A: 401 requirement=auth-token, resource token (aud is the AS)
    A->>PS: POST auth token request
    PS->>AS: POST token (federation), signed by the PS
    AS->>O: approval needed (Authorizer defers)
    O-->>AS: approve
    AS-->>PS: auth token
    PS-->>A: auth token
    A->>R: GET /ledger, auth token
    R-->>A: 200
```

If the AS denies, the PS relays the refusal and the agent gets an error
instead of a token. With the collapsed deployment, the PS-to-AS step is an
in-process call (`Server.Local`) and nothing else changes.

## 6. A mission

A mission is a task the person approves once. The agent proposes it, the PS
returns a digest that names it exactly, and later tokens carry the digest, so
the AS or PS can judge each request against the task.

```mermaid
sequenceDiagram
    participant A as Agent
    participant PS as Person Server
    participant P as Person

    A->>PS: POST mission, description
    PS->>P: approve the mission (MissionApprover)
    P-->>PS: approved
    PS-->>A: mission with mission_s256

    Note over A,PS: Tokens requested under the mission carry mission_s256
    A->>PS: POST audit, action and result
    PS-->>A: 201
    A->>PS: POST mission, progress update
    PS-->>A: 200
    A->>PS: POST mission, completion summary
    PS->>P: review the completion
    P-->>PS: accepted
    PS-->>A: 200 (mission terminated, completed)
```

Set `Transport.MissionS256` and person and auth tokens are requested under the
mission. The PS keeps a log of each approval, token request, audit entry,
update, and completion. A terminated mission returns `*MissionStatusError`
from every PS endpoint.

## 7. Permission

For an action that is not a resource call, such as sending an email, the agent
asks the PS first. This works with or without a mission.

```mermaid
sequenceDiagram
    participant A as Agent
    participant PS as Person Server
    participant PD as PermissionDecider (your code)

    A->>PS: POST permission, action and description
    PS->>PD: decide
    PD-->>PS: granted or refused
    PS-->>A: 200 granted (or a reason)
```

## 8. The resource asks the person directly

A resource may need its own interaction before authorizing, such as a consent
screen of its own. It answers with a `202` and `requirement=interaction`
(§6.2), and `Transport` follows it the same way as the PS consent flow in
section 4: it shows the URL and code through `OnRequirement` and polls the
pending location. A resource can also hand back an `AAuth-Access` session token
that is bound into later signatures and refreshed on any response.

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource
    participant P as Person

    A->>R: POST /orders
    R-->>A: 202, Location, requirement=interaction (url, code)
    A-)P: show the url and code
    P->>R: complete the resource's own interaction
    A->>R: GET Location (poll)
    R-->>A: 200
```

## 9. Call chaining

A resource that must call another resource to serve a request acts as an agent
itself. It has its own agent provider, identity, and key. It takes the PS from
the upstream token it received, and sends that token as `upstream_token`, so the
downstream tokens are issued for the same person and mission.

```mermaid
sequenceDiagram
    participant A as Agent
    participant R1 as Resource 1 (acts as an agent)
    participant PS as Person's PS
    participant R2 as Resource 2

    A->>R1: request, auth token
    R1->>R1: RouteDownstream(upstream token)
    R1->>R2: request, signed as R1
    R2-->>R1: 401 requirement=person-token
    R1->>PS: POST person token request, upstream_token
    PS-->>R1: person token (no later than the upstream token)
    R1->>R2: request, person token
    R2-->>R1: 401 requirement=auth-token
    R1->>PS: POST auth token request, upstream_token
    PS-->>R1: auth token
    R1->>R2: request, auth token
    R2-->>R1: 200
    R1-->>A: 200
```

If the downstream resource needs a person, R1 can pass the interaction on to its
own caller with `ChainInteraction`, which returns R1's own `202`, and finishes
the original request when the person completes it.

## 10. Sub-agents

An agent can run a sub-agent with its own key, one level deep. The parent signs
the requests to the PS and attaches the sub-agent's token as `subagent_token`,
so the person and auth tokens bind the sub-agent's key. The sub-agent signs its
own requests to resources.

```mermaid
sequenceDiagram
    participant S as Sub-agent
    participant P as Parent agent
    participant AP as Agent provider
    participant PS as Person Server
    participant R as Resource

    P->>AP: sub-agent token request, signed with its agent token
    AP-->>P: sub-agent token (parent_agent, its own key, exp no later than the parent's)
    S->>R: GET, sub-agent token
    R-->>S: 401 requirement=person-token
    S->>P: via the parent's PSClient
    P->>PS: POST person token request, subagent_token
    PS-->>P: person token bound to the sub-agent's key
    P-->>S: person token
    S->>R: GET, person token
```

## 11. Revocation

Revoking an agent token cascades. The agent provider tells the PS, the PS
revokes what it issued to that agent at each resource, and an AS revokes its own
auth tokens at the resource.

```mermaid
sequenceDiagram
    participant AP as Agent provider
    participant PS as Person Server
    participant AS as Access Server
    participant R as Resources

    AP->>PS: POST revoke, agent token jti
    PS->>R: POST revoke, person and auth tokens it issued
    R-->>PS: 200
    PS->>AS: POST revoke, the person token it presented
    AS->>R: POST revoke, the auth token it issued
    R-->>AS: 200
    AS-->>PS: 200
    PS-->>AP: 200
```

Afterwards the resource rejects the cached tokens, and the PS rejects the
revoked agent token, so the agent obtains nothing new. `Transport` drops a
cached person or auth token that a resource reports as expired or revoked, and
falls back to the next credential.

## Errors and waiting

Two behaviors apply to every flow above:

- **Deferred responses.** Any endpoint can answer `202` with a `Location`, and
  `Retry-After`. The agent polls with signed GETs, backs off on `429`, and stops
  on a non-`202` answer.
- **Failures.** A signature problem is a `401` with a `Signature-Error` code.
  Token endpoint and polling problems are RFC 9457 problem bodies. A
  `clock_skew` error makes `Transport` wait out the skew and send the same
  request once more.
