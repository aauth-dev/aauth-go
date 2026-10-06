// Package aauth implements the AAuth protocol
// (draft-hardt-oauth-aauth-protocol-09): agent identity and authorization
// across trust domains, without shared secrets or per-server pre-registration.
// Every agent gets its own signing key (Ed25519 by default, or ES256 — any
// crypto.Signer, so hardware-backed keys work) and a self-describing token
// that binds that key; any party can verify it.
//
// # Layers
//
// AAuth stacks these concerns, each usable independently:
//
//   - Identity — an agent proves who it is on every request. See [Agent] and
//     [Agent.MintToken] for minting an aa-agent+jwt, [SignRequest] and
//     [VerifyAndExtractAgent] for the RFC 9421 HTTP message-signature profile
//     over the Signature-Key carrier (draft-hardt-httpbis-signature-key-04).
//   - Person identity — a Person Server identifies the person an agent acts
//     for to one resource with a person token (draft -11 §7.1). See
//     [IssuePersonToken] (PS side) and [VerifyAndExtractPerson] (resource
//     side).
//   - Resource access — a protected API decides what an agent may do. See
//     [Transport] (the agent-side client that turns 401 challenges into token
//     exchanges automatically), [PSClient.RequestAuthToken] (three-party
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

// JWT typ header values (draft -11 §5.3.1, §6.7.1, §7.1.2, §9.4.1). A
// recipient MUST check typ before acting on any AAuth JWT (§11.5.1).
const (
	TypAgent    = "aa-agent+jwt"
	TypPerson   = "aa-person+jwt"
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
	// HeaderAAuthAccess carries a session token from a resource to an
	// agent (draft -11 §6.3); the agent returns it as
	// "Authorization: AAuth <session token>", covered by its signature.
	HeaderAAuthAccess = "AAuth-Access"
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
	// ErrClockSkew means a signature's created (or a token's iat) is further
	// ahead of the verifier's clock than its validity window — the sender's
	// clock disagrees with the verifier's (signature-key §5.4.14).
	ErrClockSkew = errors.New("aauth: clock skew")
	// ErrSignatureInput means Signature-Input does not cover the components
	// the verifier requires (signature-key §5.4.5); see
	// [MissingComponentsError].
	ErrSignatureInput = errors.New("aauth: signature does not cover required components")
	// ErrUnsupportedScheme means the Signature-Key member for the label
	// names a scheme the verifier does not implement (signature-key §5.4.2).
	ErrUnsupportedScheme = errors.New("aauth: unsupported Signature-Key scheme")
	// ErrUnknownKey means no key with the requested kid was found at the
	// issuer's jwks_uri (signature-key §5.4.8).
	ErrUnknownKey = errors.New("aauth: unknown key")
	// ErrIssuerMissing means a discovered metadata document has no issuer
	// member (signature-key §5.4.9; draft -11 §11.2).
	ErrIssuerMissing = errors.New("aauth: metadata issuer missing")
	// ErrIssuerMismatch means a discovered metadata document's issuer
	// differs from the identity it was fetched under (signature-key
	// §5.4.10; draft -11 §11.2).
	ErrIssuerMismatch = errors.New("aauth: metadata issuer mismatch")
	// ErrRevoked means a token verified and is unexpired but its issuer has
	// withdrawn it (signature-key §5.4.13). This package does not track
	// revocations; a deployment's revocation check returns (or wraps) it so
	// that [SignatureErrorFor] answers revoked_jwt.
	ErrRevoked = errors.New("aauth: token revoked")
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
