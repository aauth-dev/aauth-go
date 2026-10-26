# Sandbox

The AAuth sandbox runs every AAuth role from this module on your machine: an agent provider, a person server (PS), an access server (AS) and two demo resources, each on its own HTTPS origin. A signing helper lets HTTP clients that cannot sign, such as Postman, Newman and curl, act as the agent.

The sandbox is a development tool. Its keys, certificate authority and automatic consent are for local use only.

## Roles

| Role | Origin | What it does |
|------|--------|--------------|
| Agent provider | `https://ap.aauth.test` | Issues agent tokens: `POST /agent-token` (two-key refresh, `jkt-jwt`), `POST /enroll` (`hwk`) |
| Person server | `https://ps.aauth.test` | Person tokens (`POST /person`), auth tokens (`POST /token`), consent at `/interaction` |
| Access server | `https://as.aauth.test` | Auth tokens for `docs.aauth.test`, federated from the PS (`POST /token`) |
| Resource | `https://resource.aauth.test` | Resource tokens name the PS (three-party) |
| Docs resource | `https://docs.aauth.test` | Resource tokens name the AS (four-party) |

Each demo resource serves:

| Path | Access mode |
|------|-------------|
| `GET /api/documents` | Agent identity (agent token), person identity (person token), or PS and federated authorization (auth token) |
| `GET /api/data` | Resource-managed access: a `202` with an interaction, a poll of `Location`, then an `AAuth-Access` session token presented as `Authorization: AAuth <token>` |
| `POST /authorize` | The authorization endpoint: a signed request presenting a person token, body `{"scope": "data.read data.write"}`, answered with a `resource_token` |

The scopes offered are `documents:read`, `data.read` and `data.write`.

## Run It

```bash
go install github.com/aauth-dev/aauth-go/cmd/aauth-sandbox@latest
aauth-sandbox serve
```

Server identifiers are `https` origins without a port (draft-11 §11.1), so the sandbox listens on port 443. macOS lets ordinary users bind it; on Linux, grant `CAP_NET_BIND_SERVICE` or run it in a container.

The roles listen on `127.0.0.1:443` and the signing helper on `127.0.0.1:8099`, on loopback only. Anyone who can reach the roles can read the trace, which holds every token, and get consent approved automatically; anyone who can reach the helper can sign requests as the test agent. `serve` refuses a non-loopback `--listen` or `--signer` address unless you also pass `--listen-any-interface` or `--signer-any-interface`. Use those flags only inside a container whose ports are published on the host's loopback address.

Point the names at your machine, once:

```bash
aauth-sandbox hosts | sudo tee -a /etc/hosts
```

The sandbox's own server-to-server requests, and requests through the signing helper, reach the roles without hosts entries. You need them only to open the consent pages in a browser or to call the roles directly.

## Run It in Docker

Docker runs the sandbox without a Go toolchain. Two Compose files are in `deploy/docker/`:

| File | Layout | Use it for |
|------|--------|------------|
| `compose.yaml` | Every role and the signing helper in one container; port 443 and the helper published on `127.0.0.1` | Day-to-day development, Postman, browsers |
| `compose.roles.yaml` | One container per role on a shared network, each answering at its `.aauth.test` name, plus the helper in its own container | Seeing traffic between roles cross a real network; testing a role in isolation |

```bash
# Every role in one container
docker compose -f deploy/docker/compose.yaml up -d --build --wait

# One container per role
docker compose -f deploy/docker/compose.roles.yaml up -d --build --wait

# Drive all five access modes through the signing helper
deploy/docker/smoke.sh http://127.0.0.1:8099
```

- **Ports.** `SIGNER_PORT` and `SANDBOX_HTTPS_PORT` change the host ports, for example `SIGNER_PORT=8199 docker compose -f deploy/docker/compose.yaml up -d`. Both are published on `127.0.0.1` only.
- **State.** The CA and keys live in a Compose volume, so they survive restarts. `docker compose … down -v` removes them. With one container per role, an `init` service creates the CA and every key before the roles start, so they never race to create them.
- **CA certificate.** `docker compose -f deploy/docker/compose.yaml exec sandbox aauth-sandbox ca export --state /state > aauth-sandbox-ca.pem`.
- **Health.** Each container's health check is `aauth-sandbox health`, which asks the roles it serves (and, with `--signer`, the helper) to answer. The image has no shell or curl.
- **Image.** `deploy/docker/Dockerfile` builds a static binary on a distroless, non-root image: `docker build -f deploy/docker/Dockerfile -t aauth-sandbox:dev .`

To run the image without Compose, publish its ports on the host's loopback address:

```bash
docker run --rm -p 127.0.0.1:443:443 -p 127.0.0.1:8099:8099 aauth-sandbox:dev
```

Do not publish them as `-p 443:443 -p 8099:8099`. Docker then listens on every interface of the host, and anyone on your network can read the trace, get consent approved and sign requests through the helper. Inside the container the sandbox listens on every interface (`--listen-any-interface`, `--signer-any-interface`), so the host-side address is the only thing that keeps it local.

The CLI options the Compose files use are available outside Docker too: `--roles ps` serves only the person server and reaches the other roles at their usual names; `--roles none` runs only the signing helper; `aauth-sandbox init` creates the CA and every key ahead of time.

## Trust the Certificate Authority

On first run the sandbox creates a certificate authority in `~/.aauth-sandbox` and a certificate for the role names. Export it and trust it only in the tools that call the sandbox:

```bash
aauth-sandbox ca export > aauth-sandbox-ca.pem
```

- **Postman:** Settings > Certificates > CA certificates, then select `aauth-sandbox-ca.pem`.
- **curl:** `--cacert aauth-sandbox-ca.pem`.
- **Go and other clients:** add it to the client's own root pool, as `sandbox.NewClient` does.
- **Browsers:** accept the warning for the consent pages, or trust the CA in a separate browser profile used only for the sandbox.

Avoid adding it to your system trust store. The CA's private key sits unencrypted in the state directory, and every program on the machine would trust what it signs.

The CA is limited to the sandbox's names. Its name constraints let it issue certificates only for the sandbox domain (`aauth.test` and its subdomains), `localhost`, any host name you serve outside the domain, and the loopback addresses; clients refuse a certificate it signs for any other site. It is valid for a year.

The sandbox replaces the CA, and logs that it did, when the CA has less than 30 days left, when it has no name constraints (a CA created by an earlier version), or when you serve a host name it does not cover, such as `--upstream api.example.dev=...`. Export it again and trust the new one wherever you trusted the old. Keep upstream names under the sandbox domain (`--upstream petstore=...` is `petstore.aauth.test`) to avoid a new CA.

## Sign Requests with the Helper

The helper listens on `http://127.0.0.1:8099`, on loopback only. Send a request to the helper with the target URL as its path; the helper signs it as the sandbox's test agent and forwards it:

```bash
curl http://127.0.0.1:8099/https://resource.aauth.test/api/documents
```

Control headers, removed before forwarding:

| Header | Values |
|--------|--------|
| `X-Sandbox-Present` | `agent` (default): the agent token; `person` or `auth`: the token in `X-Sandbox-Token`; `hwk`; `jkt-jwt`: a naming JWT from the agent's durable key; `none`: forward unsigned |
| `X-Sandbox-Token` | The token to present. For `agent` it replaces the helper's own agent token |
| `X-Sandbox-Capabilities` | The capabilities the agent declares (default `interaction`; empty for none) |

Without `X-Sandbox-Present` or `X-Sandbox-Token`, the helper signs as the request's own `Signature-Key` says, the way a signing proxy receives requests from clients that cannot sign, such as Postman collections that [pidl](https://github.com/grokify/pidl) generates with `--signer proxy`:

| `Signature-Key` received | The helper |
|--------------------------|------------|
| `sig=jwt;jwt="<token>"` | Presents the token as the agent, person or auth token its `typ` names |
| `sig=jwt`, or none | Presents its own agent token |
| `sig=hwk`, `sig=jkt-jwt` | Signs with that scheme |

The helper adds `Content-Digest` to bodies and signs `@method`, `@authority`, `@path`, `signature-key`, and `content-digest`, `content-type` and `authorization` when present. It declares the agent's capabilities as `AAuth-Capabilities` to the resources, and as a `capabilities` member in JSON bodies sent to the PS when the body has none. Responses come back unchanged.

`POST /sign` with `{"method", "url", "headers": [[name, value]], "body", "present", "token"}` returns the headers to add, for clients that send requests themselves.

The helper is for tools on your machine, not for web pages:

- **Hosts it answers at.** It answers only when the request's `Host` is `localhost`, a loopback address or the address it listens on. That keeps a web page from reaching it through a DNS name pointed at `127.0.0.1`. Add another name with `--signer-host`, for example the service name another container uses to reach it.
- **Browser requests.** It refuses requests that carry `Origin`, or `Sec-Fetch-Site` set to `cross-site` or `same-site`, which browsers add for requests made by web pages. curl, Postman and Newman send neither. It answers `OPTIONS` itself and does not forward it.
- **Targets.** It signs and forwards only to the sandbox's role origins, including `--remote` ones, and its `--upstream` hosts. Pass `--signer-any-target` to `serve` to sign for any `https` host.
- **Redirects.** It returns a redirect to you as it received it and never follows it, so a signed request goes only to the URL you named.

### A Full Flow with curl

```bash
H=http://127.0.0.1:8099

# Agent token (two-key refresh)
AT=$(curl -s -X POST -H 'X-Sandbox-Present: jkt-jwt' -H 'Content-Type: application/json' -d '{}' \
  $H/https://ap.aauth.test/agent-token | jq -r .agent_token)

# Person token for the resource
PT=$(curl -s -X POST -H "X-Sandbox-Token: $AT" -H 'Content-Type: application/json' \
  -d '{"resource": "https://resource.aauth.test"}' $H/https://ps.aauth.test/person | jq -r .person_token)

# Resource token from the authorization endpoint
RT=$(curl -s -X POST -H 'X-Sandbox-Present: person' -H "X-Sandbox-Token: $PT" -H 'Content-Type: application/json' \
  -d '{"scope": "data.read data.write"}' $H/https://resource.aauth.test/authorize | jq -r .resource_token)

# Auth token from the PS; consent is automatic
AUTH=$(curl -s -X POST -H "X-Sandbox-Token: $AT" -H 'Prefer: wait=10' -H 'Content-Type: application/json' \
  -d "{\"resource_token\": \"$RT\", \"presented_token\": \"$PT\"}" $H/https://ps.aauth.test/token | jq -r .auth_token)

# Call the API with the auth token
curl -s -H 'X-Sandbox-Present: auth' -H "X-Sandbox-Token: $AUTH" $H/https://resource.aauth.test/api/documents
```

If the token request answers `202`, follow its `Location` with `GET`, signed as the agent, until it answers `200`. `Location` values are absolute URLs.

## Consent

`--consent auto` (the default) approves every interaction for `--person` (default `alice`) as soon as it is created. With `--consent manual`, open the `url` of the `AAuth-Requirement` in a browser and approve, or approve headlessly:

```bash
curl -X POST "https://ps.aauth.test/sandbox/approve?code=ABCD-EFGH" --cacert aauth-sandbox-ca.pem
```

## Trace

Every message the local roles send and receive is recorded, including the PS-to-AS federation that a client never sees:

```bash
aauth-sandbox trace          # print
aauth-sandbox trace --clear  # clear
```

The same list is at `GET https://<any role host>/sandbox/trace`; `DELETE` clears it. The trace holds every token the roles exchanged, so it refuses requests from web pages (those carrying `Origin`, or `Sec-Fetch-Site` set to `cross-site` or `same-site`). Opening it directly in a browser works.

## Use It from Other Containers

A client or resource in its own container reaches the sandbox over a Compose network. Three things make that work:

- **Names.** Give the sandbox service the role names as network aliases, so a container resolves `ap.aauth.test`, `ps.aauth.test` and the rest, and any `--upstream` name, to it.
- **The CA.** Mount the sandbox's state volume read-only (`state:/state:ro`) and point the client at `/state/ca.pem`. The Petstore example below passes it as `--ca-file`.
- **The helper.** A tool that calls the signing helper by service name, such as Newman, needs `--signer-host <service>`, because the helper answers only loopback names otherwise.

```yaml
services:
  sandbox:
    image: aauth-sandbox:dev
    command: ["serve", "--state", "/state",
              "--signer", "0.0.0.0:8099", "--signer-any-interface", "--signer-host", "sandbox",
              "--upstream", "petstore=http://petstore:8080"]
    volumes:
      - state:/state
    networks:
      default:
        aliases: [ap.aauth.test, ps.aauth.test, as.aauth.test, resource.aauth.test, docs.aauth.test, petstore.aauth.test]
  petstore:
    image: petstore-server:dev
    command: ["--listen", ":8080", "--auth", "aauth",
              "--url", "https://petstore.aauth.test",
              "--trust", "https://ps.aauth.test",
              "--ca-file", "/state/ca.pem"]
    volumes:
      - state:/state:ro
volumes:
  state:
```

The image's default command already listens on every interface, so a command of your own needs only the options you add. Do not drop `--listen-any-interface` if you replace the whole command: without it the roles listen on loopback and other containers get "connection refused".

## Test Another Implementation

Replace a role with an external implementation with `--remote`:

```bash
aauth-sandbox serve --remote ps=https://ps.example.com
```

The sandbox stops serving that role and calls the external origin instead: agent tokens name it as the agent's PS, and resources name it as the audience of their resource tokens. The signing helper signs for the external origin too.

## Front Your Own Server

Run a resource you are developing behind the sandbox with `--upstream`:

```bash
petstore-server --listen 127.0.0.1:8080 &
aauth-sandbox serve --upstream petstore=http://127.0.0.1:8080
```

The sandbox serves `https://petstore.aauth.test` with its CA and passes each
request to the server with its `Host` header, so the server's identifier is
`https://petstore.aauth.test` and signatures over `@authority` still verify.
Its traffic appears in the trace, and the signing helper reaches it like a
role. Add the name to your hosts entry (`aauth-sandbox hosts --upstream
petstore=...` prints it). The server itself fetches the PS's keys from
`https://ps.aauth.test`, so it must trust the sandbox CA.

An agent of your own enrolls at the sandbox's agent provider with
`agentprovider.Client.Enroll`, then calls the server through
`aauth.Transport`:

```go
ap := &agentprovider.Client{BaseURL: "https://ap.aauth.test",
	Paths: agentprovider.Paths{Token: sandbox.PathEnroll}, HTTPClient: hc}
agent, err := ap.Enroll(ctx, key, nil)
if err != nil {
	return err
}
ps := aauth.NewPSClient(agent.PS, agent)
ps.HTTPClient = hc
client := &http.Client{Transport: aauth.NewTransport(agent, ps)}
res, err := client.Get("https://petstore.aauth.test/pets")
```

## State

`~/.aauth-sandbox` (or `--state`) holds the CA (`ca.pem`, `ca-key.pem`) and each role's key under `keys/`. Keys persist across restarts, so tokens and thumbprints stay stable. Delete the directory to start over.
