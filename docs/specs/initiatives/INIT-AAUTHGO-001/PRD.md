# PRD — aauth-go v0.3.0

**Initiative:** `INIT-AAUTHGO-001`
**Repository:** `github.com/aauth-dev/aauth-go`

## Problem

v0.2.0 implements nearly all of `draft-hardt-oauth-aauth-protocol-11`, `draft-hardt-httpbis-signature-key-09` and `draft-hardt-aauth-bootstrap-02`. The remaining gaps block complete AAuth walkthroughs and real deployments:

- **Protocol-11:** no agent-side client for the resource authorization endpoint (§6.6); `AAuth-Capabilities` is never sent (§11.7); a 402 payment response is only reported as an error (§6.5, §9.1.2, §11.8).
- **Bootstrap-02:** an agent cannot rotate its ephemeral key with each refresh (§8.1), one operator cannot run many self-hosted agents (§4.3.1), and there is no attestation nonce helper (§8.3, §11.4). The README has no bootstrap coverage table.
- **Rich Resource Requests** (`draft-hardt-aauth-r3-00`) are not implemented.
- **Teaching material:** `Transport` hides the protocol's messages inside one `hc.Get`, which is right for applications but cannot show a learner each step. Walkthroughs (such as PIDL's AAuth viewer) need small, tested Go snippets per step and a record of the real HTTP traffic to check their examples against.

## Goals

- Close every implementable gap in the three drafts v0.2.0 targets, and add R3.
- Provide tested, step-sized Go samples for every AAuth walkthrough scenario, marked so documentation tools can quote them.
- Export the end-to-end test traffic as JSON so documentation examples can be checked against what the SDK actually sends.

## Non-Goals

- **The Signature-Key `x509` scheme.** Protocol-11 requires agents to sign with `jwt` and servers with `jwks_uri` (§11.3.2), and a server answers any other scheme with `unsupported_scheme`. `x509` has no role in AAuth-11; it may come later as a separate package for non-AAuth use.
- **A mission control plane endpoint.** §8.6 leaves status, termination and delegation queries to a companion specification that does not exist yet; an invented endpoint would not interoperate.
- **Payment rails** (x402, card networks, settlement). The SDK carries the protocol shape and a hook; rails are integrations.
- Vendor attestation implementations (platform-specific verifiers stay behind `AttestationVerifier`).

## Requirements

### Protocol-11

1. **Capabilities (§11.7).** Constants for `interaction`, `clarification` and `payment`; formatting and parsing of the RFC 9651 list; `Transport` sends `AAuth-Capabilities` on signed requests to resources, as the union of the agent's capabilities and the mission's approved capabilities; resources can read the header, and the challenge helpers do not raise `interaction` to an agent that did not declare it.
2. **Authorization endpoint (§6.6).** An agent-side `Authorize` that sends the signed request with a person token and `scope` (and `account`), and handles each outcome: `authorized` (with an optional `AAuth-Access` session token), a deferred interaction, or a resource token that it verifies (§6.7.3) and exchanges at the PS; errors map to problem types (`invalid_request`, `invalid_scope`, `invalid_account`). A resource-side handler helper decides over verified person claims.
3. **Mission termination (§8.6, §8.8).** `MissionStatusError` exposes the termination reason, keeps unknown reasons opaque, and says whether re-proposal makes sense (`expired`, `superseded`) or not (`revoked`); `mission_control_endpoint` is carried in PS metadata.
4. **Payment (§6.5, §9.1.2, §11.6, §11.8.4, §7.6.1).** A `PaymentRequiredError` carrying `Location`, the `AAuth-Requirement`, `WWW-Authenticate: Payment` challenges and an x402 body as opaque data; a `PaymentHandler` hook that `Transport` and the PS federator call before polling `Location`; interaction requests of type `payment`; a per-AS billing hook on the PS.

### Bootstrap-02

5. **Coverage table** for bootstrap-02 in the README and `docs/specs/protocol-coverage.md`, like protocol-11's.
6. **Key rotation on refresh (§8.1).** A token source that generates a new ephemeral key per two-key refresh and switches the agent's signing key and token together; person and auth tokens bound to the old key are dropped (§8.5).
7. **Many agents, one operator (§4.3.1).** A self-hosted helper that issues one agent token per agent key under a separate provider key that is never an agent key.
8. **Attestation nonces (§8.3, §11.4).** Single-use nonces with a five-minute maximum lifetime, issued and checked by the agent provider for enrollment and re-attestation.

### Rich Resource Requests (`draft-hardt-aauth-r3-00`)

9. **Types and discovery:** R3 documents, operations for the seven vocabularies (`mcp`, `openapi`, `grpc`, `graphql`, `asyncapi`, `wsdl`, `odata`), `r3_vocabularies` in resource metadata, the `per-call` access mode, and `r3_s256` over served bytes.
10. **Documents:** a byte-pinned document store and handler that serves only to an AS or PS signing under `jwks_uri` and entitled by the resource token; a fetch that checks the digest.
11. **Tokens:** `r3_uri` and `r3_s256` on resource tokens; `r3_uri`, `r3_s256`, `r3_granted` and `r3_per_call` on auth tokens. Issuers verify the hash, record an audit entry with issuance, and may narrow the grant; in four-party access the PS checks the AS's R3 claims against the resource token and the document.
12. **Authorization:** `Authorize` accepts `r3_operations` instead of, or with, `scope`; resources validate requested operations and compose one document across definitions.
13. **Enforcement:** resources decide per call: granted, per-call, or denied. Per-call operations produce a proposal (an R3 document with parameter digests and display detail); per-call grants are single-use and their parameters are compared structurally.

### Samples and Traces

14. **Walkthrough samples** (`examples/walkthrough`): one test file per AAuth scenario, with one small function per protocol step written with the lower-level API (sign, parse the requirement, verify the resource token, exchange, retry), wrapped in `pidl:begin <name>` and `pidl:end <name>` comments, running against the end-to-end test deployment. Region names are stable and documented.
15. **JSON trace** of the end-to-end tests (`AAUTH_E2E_TRACE_JSON=<file>`): each exchange with sender and receiver role names, method, URL with role-named hosts (`ps.example`, `as.example`), headers and bodies, in order, so tools can compare documentation examples with real traffic. Values that change per run (timestamps, keys, signatures, nonces) are marked, not compared.

### Release

16. CHANGELOG, migration notes, release notes and coverage tables for v0.3.0; v0.2.0's changelog entry dated.

## Success Criteria

- The coverage tables show every implementable section of protocol-11, signature-key-09 (except `x509`), bootstrap-02 and r3-00 as implemented and tested.
- The end-to-end tests run a four-party R3 scenario with a per-call operation, and a payment-required federation with a fake payment handler.
- Every walkthrough region compiles, runs in `go test`, and resolves from PIDL by name.
- The JSON trace for the four-party deployment validates against its published schema.

## Decisions

- **x509 and the mission control plane are deferred** for the reasons above.
- **R3 lands in phases:** types, documents and claims first; per-call enforcement second.
- **Samples are tests.** Snippets that are not compiled and run go stale; region markers in test files keep them quotable without exporting example code from the module.
