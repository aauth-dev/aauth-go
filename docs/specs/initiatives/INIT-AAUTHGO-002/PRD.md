# PRD — AAuth sandbox

**Initiative:** `INIT-AAUTHGO-002`
**Repository:** `github.com/aauth-dev/aauth-go`

## Problem

AAuth has four server roles: agent provider, resource, person server (PS) and access server (AS). Trying a flow end to end, testing an implementation of one role, or running a workshop needs all of them running together with real keys, real tokens and real HTTP message signatures. aauth-go implements every role, and its end-to-end tests and walkthrough examples already wire them up in-process, but nothing packages them as servers that a developer, an HTTP client such as Postman, or another implementation can talk to.

Two things make this harder than starting four HTTP servers:

- **Server identifiers are `https://` origins with a domain name and no port** (draft-11 §11.1). A laptop setup needs TLS, distinct hostnames per role, and port 443.
- **Every request is signed** (RFC 9421) with an Ed25519 or ES256 key, presenting a token in `Signature-Key`. General-purpose HTTP clients cannot do this themselves.

## Goals

- One command starts every role on a laptop, with trusted TLS, hostnames per role, and all five access modes available.
- Any role can be replaced by an external implementation, so the sandbox can test someone's PS, AS, resource or agent provider.
- HTTP clients that cannot sign (Postman, curl, Newman) can still drive the agent side of every flow.
- The same binary runs as one container per role in Docker Compose, and as separate deployments on minikube.
- Every message the sandbox's roles send and receive is recorded, so tools can show the server-to-server steps a client never sees.

## Non-Goals

- Production deployment, high availability, or durable storage beyond local files.
- A user interface beyond minimal consent and interaction pages.
- An HTTP (non-TLS) mode for the protocol. The sandbox runs AAuth as specified; there is no bypass in the SDK.

## Requirements

### Topology and identity

1. **Roles.** A sandbox configuration lists roles: an agent provider, a PS, an AS, and resources. Each role is `local` (served by the sandbox) or `remote` (an external URL). Two demo resources cover the access modes: one whose resource tokens name the PS (agent identity, resource-managed, person identity, PS authorization) and one with its own AS (federated authorization).
2. **Names.** Default hostnames use the reserved `.test` domain: `ap.aauth.test`, `resource.aauth.test`, `docs.aauth.test`, `ps.aauth.test`, `as.aauth.test`. `aauth-sandbox hosts` prints the `/etc/hosts` lines for a laptop.
3. **TLS.** On first run the sandbox creates a development certificate authority in its state directory and issues certificates for the configured names. `aauth-sandbox ca export` writes the CA certificate for Postman, browsers or the system trust store.
4. **One listener.** Locally, all roles share one TLS listener on port 443 and are routed by host name, because identifiers cannot carry ports.
5. **Keys.** Each role's signing key is generated on first run and persisted. `--fixed-keys` uses the published test keys from the walkthrough (RFC 8037's Ed25519 example key and the walkthrough's generated keys), so messages carry the same thumbprints the PIDL viewer shows. Fixed keys are refused for names outside `.test`.

### Flows

6. **Demo resources** serve a small documents API with the endpoints the walkthrough uses: signed access for agent identity, interaction and an `AAuth-Access` session for resource-managed access, person-token access, an authorization endpoint, and auth-token access.
7. **Consent.** The PS and the resource-managed resource serve minimal consent and interaction pages. `consent: auto` approves immediately; `consent: manual` waits for a person in a browser. In sandbox mode a headless approval endpoint lets automated runs approve a pending interaction by code.
8. **Agent.** The sandbox holds a test agent: it enrolls with the agent provider and keeps a current agent token, for use by the signing helper.

### Clients that cannot sign

9. **Signing helper.** `aauth-sandbox sign` listens on loopback only. A client sends an unsigned request to `http://127.0.0.1:<port>/<target URL>`; the helper adds `Content-Digest` for bodies, presents a token in `Signature-Key` (the agent token by default, or the token the client passes in a sandbox-only header), signs with the agent's key, forwards the request over TLS, and returns the response unchanged. It also answers `POST /sign` with the headers to add, for clients that send requests themselves.
10. **Token presentation.** The client chooses the presented token with `X-Sandbox-Present: agent|person|auth` and, for person and auth tokens, `X-Sandbox-Token`. The helper strips both before forwarding.

### Observability

11. **Trace.** Every message a local role sends or receives is recorded in the JSON trace format of the end-to-end tests (`RMI-AAUTHGO-016`): sender and receiver roles, method, URL, status, ordered headers and bodies, and pointers to per-run values. `GET /sandbox/trace` returns it; `DELETE /sandbox/trace` clears it; `--trace-file` writes it continuously.

### Packaging

12. **CLI** `aauth-sandbox` with `serve`, `sign`, `ca init|export`, `keys`, `hosts` and `trace`, built with Cobra, installable with `go install`.
13. **Docker.** One small image runs any role (`serve --role ps`) or all of them. A Compose file runs one container per role on a shared network with the `.test` names as network aliases, a volume for the CA and keys, and health checks.
14. **Kubernetes.** Kustomize manifests with a minikube overlay: a Deployment and Service per role, an Ingress with the five host names and TLS from the sandbox CA, and instructions for `minikube tunnel` and hosts entries.

### Safety

15. The sandbox is a development tool. It prints a banner saying so, refuses fixed keys outside `.test`, serves sandbox-only endpoints (headless approval, trace) only in sandbox mode, and binds the signing helper to loopback only.

## Success Criteria

- `aauth-sandbox serve` followed by the walkthrough's requests through the signing helper completes all five access modes, with the trace showing the PS-to-AS federation.
- Replacing the PS with an external URL runs the same flows against that PS.
- `docker compose up` and the minikube overlay run the same flows with each role in its own container.
- A Postman collection generated by PIDL runs green against the sandbox in Newman.

## Decisions

- **Built from aauth-go's own servers,** so the sandbox exercises the code the Go samples show.
- **TLS and real names, no HTTP shortcut.**
- **The CLI lives in the root module.** Cobra and YAML become requirements of the module, but module graph pruning keeps them out of builds that import only the library, and `go install` works from a normal release tag.
