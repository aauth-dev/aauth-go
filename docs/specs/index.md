# Specifications

aauth-go implements the AAuth drafts below. They are works in progress, and
each revision can change the wire format; the module's minor version moves
with them until the protocol stabilizes.

| Draft | Version | Constant |
|---|---|---|
| [AAuth Protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) | `draft-hardt-oauth-aauth-protocol-11` | `aauth.ProtocolDraft` |
| [HTTP Signature Keys](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/) | `draft-hardt-httpbis-signature-key-09` | `aauth.SignatureKeyDraft` |
| [AAuth Bootstrap](https://datatracker.ietf.org/doc/draft-hardt-aauth-bootstrap/) | `draft-hardt-aauth-bootstrap-02` | `aauth.BootstrapDraft` |

- [Protocol coverage](protocol-coverage.md) records, section by section,
  what this module implements.
- The protocol itself is specified upstream; this site does not copy it.
  For an interactive tour, see [explorer.aauth.dev](https://explorer.aauth.dev/).
