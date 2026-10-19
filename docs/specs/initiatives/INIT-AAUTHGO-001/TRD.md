# TRD — aauth-go v0.3.0

**Initiative:** `INIT-AAUTHGO-001`
**Repository:** `github.com/aauth-dev/aauth-go`

Draft texts: `draft-hardt-oauth-aauth-protocol-11`, `draft-hardt-httpbis-signature-key-09`, `draft-hardt-aauth-bootstrap-02` (informational; its guidance is lowercase), `draft-hardt-aauth-r3-00`. These are the latest published versions.

## 1. Capabilities

```go
const (
    CapabilityInteraction   = "interaction"
    CapabilityClarification = "clarification"
    CapabilityPayment       = "payment"
)
func FormatCapabilities(caps []string) string            // RFC 9651 List of Tokens
func RequestCapabilities(r *http.Request) []string      // unknown values ignored by callers
// Transport gains Capabilities []string; the header is added before signing,
// only on requests to resources (PS endpoints use the body array).
```

## 2. Authorization Endpoint

```go
type AuthorizeRequest struct {
    Scope        string
    Account      string
    R3Operations *r3.Operations
}
type AuthorizeResult struct {
    Status       string // "authorized"
    Scope        string
    SessionToken string // AAuth-Access, when issued
    AuthToken    string // when the resource returned a resource token and the exchange completed
}
func (t *Transport) Authorize(ctx context.Context, resource string, req AuthorizeRequest) (*AuthorizeResult, error)
func AuthorizationHandler(self string, verify TokenVerifyOptions, decide func(context.Context, *PersonClaims, AuthorizeRequest) (AuthorizeDecision, error)) http.Handler
```

The endpoint comes from resource metadata (`authorization_endpoint`). `Authorize` obtains the person token through the PS client, follows 202 interaction, verifies a returned resource token per §6.7.3, and exchanges it.

## 3. Mission Termination

`MissionStatusError` gains `Reason string` and `Repropose() bool`. `PersonServerMetadata` gains `MissionControlEndpoint` (carried, not served).

## 4. Payment

```go
type PaymentRequiredError struct {
    Location        string
    Requirement     *Requirement
    WWWAuthenticate []string        // Payment challenges, unparsed beyond auth-params
    X402            json.RawMessage // opaque
}
type PaymentHandler interface {
    Settle(ctx context.Context, p *PaymentRequiredError) error
}
```

`Transport` and `personserver` (as federator) call `Settle`, then poll `Location` through the existing deferred loop. Without a handler the error is returned. `RequestInteraction` accepts `Type: "payment"`.

## 5. Bootstrap

- `agentprovider.RotatingAgent`: holds the durable key, creates an ephemeral key per refresh, and swaps `{key, agent token}` atomically; `Transport` reads both from it. The PS client's per-key caches drop tokens for retired keys.
- `aauth.Operator`: a provider key plus `IssueAgentToken(agentPub, name)` for many self-hosted agents; refuses the provider key as an agent key.
- `agentprovider.NonceStore` with `Issue` and `Consume` (single use, at most five minutes); `AttestationVerifier` receives the nonce.

## 6. R3

```go
// package r3
type Operations struct {
    Vocabulary string            `json:"vocabulary"`
    Operations []json.RawMessage `json:"operations"` // shape per vocabulary
}
type Document struct {
    Vocabulary string            `json:"vocabulary"`
    Operations []json.RawMessage `json:"operations"`
    Account    string            `json:"account,omitempty"`
    Display    Display           `json:"display"`
    Parameters map[string]Digest `json:"parameters,omitempty"` // per-call proposals
    Result     *Digest           `json:"result,omitempty"`
}
type Digest struct{ S256, Excerpt, MediaType string }
func Hash(served []byte) string                               // base64url SHA-256
type Store interface { Put(doc []byte) (uri, s256 string, err error); Get(uri string) ([]byte, error) }
func Handler(store Store, entitled func(ctx context.Context, signer string, uri string) bool) http.Handler
func Fetch(ctx context.Context, signer aauth.ServerSigner, uri, s256 string) (*Document, []byte, error)
type Matcher interface { Match(granted []json.RawMessage, op json.RawMessage) bool } // one per vocabulary
func Enforce(claims *aauth.AuthClaims, op json.RawMessage, m Matcher) Decision      // Granted | PerCall | Deny
```

- Bytes are stored exactly as served; there is no canonicalization.
- The handler requires `VerifyServerRequest` and refuses agents.
- Claims: `ResourceTokenParams.R3URI`/`R3S256`; `AuthClaims.R3URI`/`R3S256`/`R3Granted`/`R3PerCall`. PS and AS issuers verify the digest, call an audit hook in the same step as issuance, and may narrow `r3_granted`.
- Per-call: the resource stores a proposal, returns it in the challenge, and consumes a matching single-use grant; parameter comparison is structural (JSON value equality), with digests checked.

## 7. Walkthrough Samples

```
examples/walkthrough/
  doc.go                     // package walkthrough: what the regions are
  deployment_test.go         // shared httptest deployment (reuses the e2e fixture shape)
  agent_identity_test.go     // pidl:begin agent-sign-request … pidl:end
  resource_managed_test.go
  ps_authorization_test.go
  federated_test.go
  missions_test.go
  r3_test.go
  bootstrap_test.go
```

Region names are `<scenario>.<step>` (for example `federated.ps-to-as`), listed in `doc.go`. Each region is 5–25 lines of user-facing code.

## 8. JSON Trace

```go
type TraceExchange struct {
    From, To string              // role names
    Request  TraceMessage
    Response TraceMessage
    Volatile []string             // JSON pointers to per-run values
}
type TraceMessage struct {
    Method, URL string            // hosts rewritten to <role>.example
    Status      int
    Headers     [][2]string       // in order
    Body        json.RawMessage
}
```

Written by the e2e tracer when `AAUTH_E2E_TRACE_JSON` names a file. A JSON Schema for the trace is generated from these types.

## Testing

Unit tests per feature; e2e scenarios for capabilities, authorization endpoint, payment with a fake handler, key rotation, R3 four-party with per-call; examples run in `go test ./...`.
