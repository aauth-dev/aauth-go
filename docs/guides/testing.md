# Testing

```bash
go test -race ./...
golangci-lint run
```

Unit tests cover token round trips and rejections, signature tampering,
replay guards, delegation rules, JWKS caching, and every server endpoint
against live `httptest` servers, and the [`e2e`](https://github.com/aauth-dev/aauth-go/tree/main/e2e) package runs every
role together (below). Runnable `Example` functions double as API documentation.

### End-to-end tests

The [`e2e`](https://github.com/aauth-dev/aauth-go/tree/main/e2e) package runs the roles together on `httptest` servers with
in-memory stores and seeded policy, so it needs no network, database, or
credentials and runs the same locally and in CI. Each deployment has an agent
provider and person server on one origin, two resources, and an enrolled
agent whose key a work session registered. Resource A uses the person server
directly (three-party); resource B uses an access server. The two tests differ
in where that access server runs:

| Test | Topology | Federation |
|---|---|---|
| `TestCollapsedDeployment` | Agent provider, person server, and access server on one origin (§9.3.3) | In-process (`Server.Local`) |
| `TestFourPartyDeployment` | Access server on its own origin (§9.1) | Over HTTP (`accessserver.Client`), signed as the PS; the test checks that requests reached the AS's token and revocation endpoints |

Both run the same scenario as subtests, in order, each skipped if an earlier
one failed:

1. three-party access at A, where Alice's approval binds the agent to her;
2. propose a mission;
3. B refuses a request outside a mission;
4. access at B under the mission, with the access server's deferred approval;
5. audit, update, and completion of the mission, checking the mission log;
6. revocation of the agent token, cascading to both resources;
7. the revoked agent obtains nothing new.

Run one topology, with the steps listed:

```bash
go test -race -v -run TestFourPartyDeployment ./e2e
```

The fixture (`newDeployment` in `e2e/fixture_test.go`) shows how to wire the
servers and seed policy; the approvals a hosting application's UI would make
run in the `Notify` hooks.

Wire-format golden vectors live in [`testdata/vectors`](https://github.com/aauth-dev/aauth-go/tree/main/testdata/vectors):
language-neutral JSON (JWK thumbprints, identifiers, header codecs, metadata
documents, deterministic Ed25519 JWTs, RFC 9421 request signatures) that
another implementation can run as a conformance check. After an intentional
wire change, regenerate the derived values and review the diff:

```bash
go test -run TestVectors -update
```
