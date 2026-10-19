# TRD — AAuth sandbox

**Initiative:** `INIT-AAUTHGO-002`
**Repository:** `github.com/aauth-dev/aauth-go`

## Packages

```
sandbox/                 library: no CLI or YAML dependencies
  config.go              Config, RoleConfig (local | remote URL), defaults
  ca.go                  development CA, certificates per name
  keys.go                key generation, persistence, fixed walkthrough keys
  resources.go           demo resources for the five access modes
  consent.go             consent and interaction pages, headless approval
  trace.go               trace recorder (RoundTripper and handler middleware)
  signer.go              signing helper handler
  sandbox.go             New(Config) (*Sandbox, error); Handler(); Close()
cmd/aauth-sandbox/       Cobra CLI: serve, sign, ca, keys, hosts, trace
deploy/docker/           Dockerfile, compose.yaml
deploy/k8s/              kustomize base and overlays/minikube
```

## Configuration

```yaml
state: ~/.aauth-sandbox        # CA, keys, enrollment
listen: :443
consent: auto                  # auto | manual
fixedKeys: false
roles:
  ap:       {host: ap.aauth.test}
  ps:       {host: ps.aauth.test}
  as:       {host: as.aauth.test}
  resource: {host: resource.aauth.test}            # resource tokens name the PS
  docs:     {host: docs.aauth.test, as: as}        # resource tokens name the AS
  # any role can be remote:
  # ps: {remote: https://ps.example.com}
```

Keys are camelCase, matching the YAML and JSON conventions of the project's other configuration.

## Routing and TLS

- A single `http.Server` with a `tls.Config.GetCertificate` that issues or loads a certificate for the SNI name, and a host-routing handler mapping each name to its role's `http.Handler`.
- Outgoing requests between local roles use an `http.Client` that trusts the sandbox CA and resolves configured names to the listener, so no hosts entries are needed for server-to-server traffic.
- `serve --role <name>` serves one role (containers); other roles are reached by name over the network.

## Signing helper

- `http://127.0.0.1:<port>/https://resource.aauth.test/api/documents` forwards to the URL after the first slash.
- Body requests get `Content-Digest` (sha-256) and `content-digest`/`content-type` coverage, as aauth-go signs today.
- `Signature-Key` presents the agent token by default; `X-Sandbox-Present` and `X-Sandbox-Token` select another token. Both headers are removed before forwarding.
- `POST /sign` with `{method, url, headers, body}` returns `{headers}` to add.
- The listener binds to `127.0.0.1` and `::1` only.

## Trace

A `RoundTripper` wrapper on outgoing clients and a middleware on role handlers record exchanges with role names resolved from hosts. The recorder is bounded (ring buffer, default 10,000 exchanges) and shares the `TraceExchange` types of the end-to-end trace (`RMI-AAUTHGO-016`).

## Docker

- Multi-stage build: `golang` builder, `gcr.io/distroless/static` runtime, non-root user, `CAP_NET_BIND_SERVICE` for 443.
- `compose.yaml`: one service per role from the same image, network aliases for the `.test` names, a shared volume for the CA (created by an init service running `ca init`), health checks on each role's metadata endpoint.

## Kubernetes

- `deploy/k8s/base`: Deployment and Service per role, ConfigMap for the sandbox configuration, Secret for the CA, Ingress with TLS for the five hosts.
- `overlays/minikube`: ingress-nginx annotations, image pull policy for local images, and a README for `minikube tunnel` and hosts entries.

## Testing

- Unit tests for configuration, CA issuance, routing, the signing helper and the trace.
- An end-to-end test runs `sandbox.New` in-process with an in-memory listener and drives the five access modes through the signing helper.
- CI builds the image and runs the end-to-end flow against Compose; the minikube run is documented and optional in CI.

## Implementation Notes

Phases 1 and 2 as built, where they differ from or refine the design above:

- **Configuration is flags, not YAML,** for now: `--state`, `--domain`, `--remote role=https://origin`, `--listen`, `--signer`, `--no-signer`, `--consent` and `--person`. `sandbox.Config` holds the same settings for library use; a YAML file can map onto it later without new dependencies in the library.
- **Paths follow the draft-11 examples:** agent provider `POST /agent-token` (two-key refresh, `jkt-jwt`) and `POST /enroll` (`hwk`); PS `POST /person`, `POST /token`, `/pending/{id}`, `/interaction`; AS `POST /token`, `/pending/{id}`; resources `GET /api/documents`, `GET /api/data`, `POST /authorize`, `/pending/{id}`, `/interaction`; every role's JWKS at `/jwks.json`.
- **One demo resource serves every access mode it can:** `/api/documents` accepts an agent, person or auth token; `/api/data` is resource-managed. The session token is accepted as `Authorization: AAuth` (draft-11 §6.3) or `AAuth-Access`.
- **Location headers are made absolute** by the sandbox router, as the draft's examples show them, so clients can follow them without knowing which server answered.
- **The signing helper declares the agent's capabilities:** `AAuth-Capabilities: interaction` to the resources, and a `capabilities` member in JSON object bodies sent to the PS when the body has none (draft-11 §7.1, §7.2), before computing the digest. `X-Sandbox-Capabilities` overrides or empties the list. Without this, the draft's `/token` example body would be answered `user_unreachable`.
- **Presentation modes** are `agent`, `person`, `auth`, `hwk`, `jkt-jwt` and `none`. The helper's agent has a durable and a current key; agent tokens from `/agent-token` through the helper are bound to the current key, so a client can pass them back in `X-Sandbox-Token`.
- **Trace types** (`sandbox.Exchange`, `sandbox.Message`) live in the sandbox package; the end-to-end JSON trace (`RMI-AAUTHGO-016`) can adopt them.
- **Fixed walkthrough keys are not implemented yet.** Keys are generated on first run and persisted, which keeps thumbprints stable across restarts.
- **Automatic consent** approves at the moment an interaction is created; a request that waits (`Prefer: wait`) may therefore answer `200` directly instead of `202`, and clients handle both.
