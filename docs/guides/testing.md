# Testing

```bash
go test -race ./...
golangci-lint run
```

Unit tests cover token round trips and rejections, signature tampering,
replay guards, delegation rules, JWKS caching, and every server endpoint
against live `httptest` servers. The [`e2e`](https://github.com/aauth-dev/aauth-go/tree/main/e2e) package runs an agent
provider, person server, access server, and two resources together.
Runnable `Example` functions double as API documentation.

Wire-format golden vectors live in [`testdata/vectors`](https://github.com/aauth-dev/aauth-go/tree/main/testdata/vectors):
language-neutral JSON (JWK thumbprints, identifiers, header codecs, metadata
documents, deterministic Ed25519 JWTs, RFC 9421 request signatures) that
another implementation can run as a conformance check. After an intentional
wire change, regenerate the derived values and review the diff:

```bash
go test -run TestVectors -update
```
