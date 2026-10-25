# PLAN — aauth-go v0.3.0

**Initiative:** `INIT-AAUTHGO-001`

## Build Order

1. **Protocol-11 gaps:** capabilities, authorization endpoint, mission termination helpers, payment. Small and independent; capabilities first because payment and R3 use it.
2. **Bootstrap:** coverage table first (it confirms the gap list), then key rotation, operator helper, nonces.
3. **R3 foundation:** types, hashing, documents, token claims, issuer checks, authorization with operations.
4. **R3 enforcement:** matchers, per-call proposals, single-use grants.
5. **Samples and trace:** walkthrough regions for existing scenarios can start early, since they use v0.2 APIs; R3 and bootstrap regions follow their features.
6. **Release:** coverage tables, changelog, migration notes, release notes; tag after CI passes.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| R3 is a -00 draft and may change | Isolate in package `r3`; phase enforcement separately |
| Region names drift and break PIDL samples | Names listed in `doc.go`; a test fails if a listed region is missing |
| Trace includes values that change per run | `Volatile` pointers; role-named hosts |
| Payment semantics depend on rails | Opaque data plus a hook; no rail code |

## Consumers

PIDL's AAuth content (`INIT-PIDL-004`) quotes the walkthrough regions as Go samples and checks its HTTP examples against the JSON trace.
