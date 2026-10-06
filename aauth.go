// Package aauth implements the AAuth protocol
// (draft-hardt-oauth-aauth-protocol-09): agent identity and authorization
// across trust domains, without shared secrets or per-server pre-registration.
// Every agent gets its own Ed25519 keypair and a self-describing token that
// binds that key; any party can verify it.
//
// # Layers
//
// AAuth stacks three concerns, each usable independently:
//
//   - Identity — an agent proves who it is on every request. See [Agent] and
//     [Agent.MintToken] for minting an aa-agent+jwt, [SignRequest] and
//     [VerifyAndExtractAgent] for the RFC 9421 HTTP message-signature profile
//     over the Signature-Key carrier (draft-hardt-httpbis-signature-key-04).
//   - Resource access — a protected API decides what an agent may do. See
//     [Transport] (the agent-side client that turns 401 challenges into token
//     exchanges automatically), [PSClient.ExchangeToken] (three-party
//     PS-asserted access), and [IssueResourceToken] / [VerifyAndExtractAuth]
//     (the resource side).
//   - Governance — optional missions, permission requests, and audit. See
//     [PSClient.RequestPermission] and [PSClient.Audit].
//
// # Deployment shapes
//
// The self-hosted / local-agent shape is a first-class target: the agent is
// its own agent provider (draft-hardt-aauth-bootstrap-01 §4.3), which is what
// autonomous coding agents on developer machines are. Verification trust is
// pluggable via [KeyResolver]: [JWKSResolver] for public discovery,
// [StaticResolver] for pinned keys (offline / air-gapped), and
// [SelfSignedResolver] for local agents.
//
// This is, to our knowledge, the first Go implementation of the protocol.
package aauth

import (
	"errors"
	"io"
)

// JWT typ header values (draft -09 §5.2.2, §6, §7).
const (
	TypAgent    = "aa-agent+jwt"
	TypResource = "aa-resource+jwt"
	TypAuth     = "aa-auth+jwt"
)

// Well-known metadata document names (draft -09 §4; used as the dwk claim
// and as /.well-known/{name} paths).
const (
	WellKnownAgent    = "aauth-agent.json"
	WellKnownPerson   = "aauth-person.json"
	WellKnownResource = "aauth-resource.json"
	WellKnownAccess   = "aauth-access.json"
)

// HTTP header names.
const (
	HeaderSignatureKey   = "Signature-Key"
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"
	HeaderSignatureError = "Signature-Error"
	HeaderPrefer         = "Prefer"
	HeaderRetryAfter     = "Retry-After"
	HeaderLocation       = "Location"
)

// DefaultSignatureLabel is the signature label used by this implementation.
// Draft examples use "sig"; RFC 9421 labels are correlated by equality
// across Signature-Input, Signature, and Signature-Key (signature-key §3).
const DefaultSignatureLabel = "sig"

// Recommended lifetimes (draft -09 §5.2.2: agent tokens SHOULD NOT exceed 24h).
const (
	MaxAgentTokenTTLSeconds = 24 * 60 * 60
)

// Sentinel errors returned across the package; match with [errors.Is].
var (
	// ErrInvalidToken means a JWT was malformed or failed verification.
	ErrInvalidToken = errors.New("aauth: invalid token")
	// ErrWrongTokenType means the JWT typ header was not the expected value.
	ErrWrongTokenType = errors.New("aauth: wrong token type")
	// ErrSignatureInvalid means an HTTP message signature failed to verify.
	ErrSignatureInvalid = errors.New("aauth: signature invalid")
	// ErrExpired means a token's exp claim is in the past.
	ErrExpired = errors.New("aauth: token expired")
	// ErrMissingSigKey means the request had no Signature-Key header.
	ErrMissingSigKey = errors.New("aauth: missing Signature-Key header")
	// ErrBadSigKey means the Signature-Key header was malformed.
	ErrBadSigKey = errors.New("aauth: malformed Signature-Key header")
	// ErrMissingClaim means a required JWT claim was absent.
	ErrMissingClaim = errors.New("aauth: required claim missing")
	// ErrSubAgentDirect means a sub-agent tried to request authorization
	// itself; its parent must request on its behalf (draft -09 §10.2).
	ErrSubAgentDirect = errors.New("aauth: sub-agent must not request authorization directly")
	// ErrUnknownAction means a clarification POST had a missing or
	// unrecognized action member (draft -09 §7.3.2).
	ErrUnknownAction = errors.New("aauth: missing or unrecognized action")
)

// closeBody closes an HTTP message body that has been consumed or is no
// longer needed. On the read side a Close error carries nothing the caller
// can act on (the bytes it needed were already read, or are being
// discarded), so it is deliberately not propagated.
func closeBody(c io.Closer) {
	_ = c.Close() // see doc comment: read-side close errors are not actionable
}

// drainBody reads the remainder of a response body and closes it so the
// underlying connection can be reused. Errors are not actionable for the
// same reason as in closeBody: the content is being discarded.
func drainBody(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, rc) // content intentionally discarded
	closeBody(rc)
}
