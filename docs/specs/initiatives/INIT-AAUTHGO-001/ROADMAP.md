# ROADMAP — aauth-go v0.3.0

**Initiative:** `INIT-AAUTHGO-001`
**Repository:** `github.com/aauth-dev/aauth-go`

Commits implementing an item carry `Refs: RMI-AAUTHGO-<NNN>`.

## Phase 1 — Protocol-11 Gaps

**Theme:** The last protocol sections

- [ ] `RMI-AAUTHGO-001` `AAuth-Capabilities`: constants, formatting and parsing, sent by `Transport`, read by resources
- [ ] `RMI-AAUTHGO-002` Authorization endpoint: agent-side `Authorize` and a resource handler helper
  - Depends on: `RMI-AAUTHGO-001`
- [ ] `RMI-AAUTHGO-003` Mission termination reasons, re-proposal guidance and `mission_control_endpoint` metadata
- [ ] `RMI-AAUTHGO-004` Payment required: error type, settlement hook in `Transport` and the PS federator, payment interactions
  - Depends on: `RMI-AAUTHGO-001`

## Phase 2 — Bootstrap

**Theme:** Agent keys over their whole life

- [ ] `RMI-AAUTHGO-005` Bootstrap-02 coverage table in the README and protocol coverage document
- [ ] `RMI-AAUTHGO-006` Ephemeral key rotation on two-key refresh, dropping tokens bound to retired keys
  - Depends on: `RMI-AAUTHGO-005`
- [ ] `RMI-AAUTHGO-007` Operator helper for many self-hosted agents under one provider key
  - Depends on: `RMI-AAUTHGO-005`
- [ ] `RMI-AAUTHGO-008` Single-use attestation nonces for enrollment and re-attestation
  - Depends on: `RMI-AAUTHGO-005`

## Phase 3 — Rich Resource Requests

**Theme:** Operations instead of scopes

- [ ] `RMI-AAUTHGO-009` `r3` package: documents, operations for seven vocabularies, hashing, resource metadata
- [ ] `RMI-AAUTHGO-010` Byte-pinned document store, server-only handler and digest-checked fetch
  - Depends on: `RMI-AAUTHGO-009`
- [ ] `RMI-AAUTHGO-011` R3 token claims, issuer digest checks, audit hook, narrowing and the four-party PS check
  - Depends on: `RMI-AAUTHGO-010`
- [ ] `RMI-AAUTHGO-012` Authorization with `r3_operations` and document composition
  - Depends on: `RMI-AAUTHGO-002`, `RMI-AAUTHGO-011`
- [ ] `RMI-AAUTHGO-013` Enforcement: per-vocabulary matchers, per-call proposals and single-use grants
  - Depends on: `RMI-AAUTHGO-011`

## Phase 4 — Samples and Traces

**Theme:** Every protocol step as tested code and real traffic

- [ ] `RMI-AAUTHGO-014` `examples/walkthrough`: region-marked, tested samples per scenario step for agent identity, resource-managed, PS, federated and mission scenarios
- [ ] `RMI-AAUTHGO-015` Walkthrough samples for bootstrap and R3 scenarios
  - Depends on: `RMI-AAUTHGO-006`, `RMI-AAUTHGO-013`, `RMI-AAUTHGO-014`
- [ ] `RMI-AAUTHGO-016` JSON trace export from the end-to-end tests, with a generated schema
- [ ] `RMI-AAUTHGO-017` End-to-end scenarios for capabilities, authorization endpoint, payment, key rotation and four-party R3
  - Depends on: `RMI-AAUTHGO-004`, `RMI-AAUTHGO-006`, `RMI-AAUTHGO-012`, `RMI-AAUTHGO-013`

## Phase 5 — Release

**Theme:** Ship v0.3.0

- [ ] `RMI-AAUTHGO-018` Coverage tables, changelog (dating v0.2.0), migration notes and v0.3.0 release notes
  - Depends on: `RMI-AAUTHGO-003`, `RMI-AAUTHGO-007`, `RMI-AAUTHGO-008`, `RMI-AAUTHGO-015`, `RMI-AAUTHGO-016`, `RMI-AAUTHGO-017`
