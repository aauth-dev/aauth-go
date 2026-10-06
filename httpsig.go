package aauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/yaronf/httpsign"
)

// The AAuth HTTP message-signature profile (draft -11 §11.3): every request
// is signed with the key from cnf.jwk, covering the four mandated
// components (each closes a request-substitution attack):
//
//	@method, @authority, @path, signature-key
//
// On a request with a body, content-digest and content-type are also
// covered. Draft -11 §11.3.3.1 requires both on bodies sent to a PS, AS, or
// revocation endpoint; covering them on every body (content-type when the
// header is present) keeps one signing path and lets resources require them
// via additional_signature_components.
// When the request carries an opaque access token (`Authorization: AAuth …`,
// §6.3), the authorization header is additionally covered — binding the
// token to the signature so it can't be replayed as a bearer credential.
func coveredComponents(hasBody, hasContentType, hasAAuthAccess bool) []string {
	base := []string{"@method", "@authority", "@path", "signature-key"}
	if hasAAuthAccess {
		base = append(base, "authorization")
	}
	if hasBody {
		base = append(base, "content-digest")
		if hasContentType {
			base = append(base, "content-type")
		}
	}
	return base
}

// requestHasBody reports whether req carries (or will carry) content.
func requestHasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

// hasAAuthAuthorization reports whether the request carries an
// `Authorization: AAuth <token68>` credential.
func hasAAuthAuthorization(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "AAuth ")
}

// ContentDigestAlg is the digest algorithm for the Content-Digest header.
const ContentDigestAlg = "sha-256"

// Signature-Key schemes used by AAuth (draft -11 §11.3.2; signature-key §3).
const (
	// SchemeJWT carries a JWT whose cnf.jwk is the signing key. Agents MUST
	// use it on AAuth resource, PS, and AS requests.
	SchemeJWT = "jwt"
	// SchemeJWKSURI identifies a server signing in its own right, whose key
	// is discovered from {id}/.well-known/{dwk} → jwks_uri → kid.
	SchemeJWKSURI = "jwks_uri"
)

// SignatureKey is one parsed member of the Signature-Key header
// (signature-key §3): a Structured Field Dictionary keyed by signature
// label whose member value is a Token naming the scheme, with parameters.
type SignatureKey struct {
	Label  string            // the dictionary key; matches the Signature-Input label
	Scheme string            // the scheme token, e.g. "jwt" or "jwks_uri"
	Params map[string]string // String-valued parameters (jwt; id, dwk, kid)
}

// AttachSignatureKey sets the Signature-Key header carrying the agent (or
// person or auth) token via the jwt scheme (signature-key §3.8), serialized
// as a Structured Field Dictionary member keyed by the signature label:
//
//	sig=jwt;jwt="eyJ..."
func AttachSignatureKey(req *http.Request, token string) {
	req.Header.Set(HeaderSignatureKey, DefaultSignatureLabel+"=jwt;jwt="+sfString(token))
}

// ParseSignatureKeyMember parses the Signature-Key header as a Structured
// Field Dictionary (RFC 9651 §3.2) and returns the member for label. A
// missing header is [ErrMissingSigKey]; a malformed header, a missing
// member for the label, or a member that is not a Token with parameters is
// [ErrBadSigKey]. Members for other labels are ignored (§3.1), whatever
// their scheme.
func ParseSignatureKeyMember(req *http.Request, label string) (SignatureKey, error) {
	vals := req.Header.Values(HeaderSignatureKey)
	if len(vals) == 0 {
		return SignatureKey{}, ErrMissingSigKey
	}
	dict, err := httpsfv.UnmarshalDictionary(vals)
	if err != nil {
		return SignatureKey{}, fmt.Errorf("%w: %w", ErrBadSigKey, err)
	}
	m, ok := dict.Get(label)
	if !ok {
		return SignatureKey{}, fmt.Errorf("%w: no member for label %q", ErrBadSigKey, label)
	}
	it, ok := m.(httpsfv.Item)
	if !ok {
		return SignatureKey{}, fmt.Errorf("%w: member %q is not an item", ErrBadSigKey, label)
	}
	scheme, ok := it.Value.(httpsfv.Token)
	if !ok {
		return SignatureKey{}, fmt.Errorf("%w: member %q scheme is not a token", ErrBadSigKey, label)
	}
	sk := SignatureKey{Label: label, Scheme: string(scheme), Params: map[string]string{}}
	if it.Params != nil {
		for _, name := range it.Params.Names() {
			v, _ := it.Params.Get(name)
			if s, ok := v.(string); ok {
				sk.Params[name] = s
			}
		}
	}
	return sk, nil
}

// ParseSignatureKey returns the JWT carried under the jwt scheme for the
// default label. Any other scheme is [ErrUnsupportedScheme] (draft -11
// §11.3.4 step 4: agents MUST use the jwt scheme).
func ParseSignatureKey(req *http.Request) (string, error) {
	sk, err := ParseSignatureKeyMember(req, DefaultSignatureLabel)
	if err != nil {
		return "", err
	}
	if sk.Scheme != SchemeJWT {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedScheme, sk.Scheme)
	}
	tok := sk.Params["jwt"]
	if tok == "" {
		return "", fmt.Errorf("%w: jwt scheme without a jwt parameter", ErrBadSigKey)
	}
	return tok, nil
}

// SignRequest signs req per the AAuth profile: sets Content-Digest when a
// body is present, then Signature-Input and Signature under the default
// label, with created set to the current time. The Signature-Key header
// MUST already be attached (it is a covered component). key may be any
// supported crypto.Signer (see [GenerateKey]); the algorithm is determined
// by the key and never sent on the wire (draft -11 §11.3.3.2).
//
// keyid SHOULD be empty: draft -11 §11.3.3.2 says agents SHOULD NOT send the
// keyid parameter, since Signature-Key identifies the key. A non-empty value
// is emitted as given (it MUST then identify the same key).
func SignRequest(req *http.Request, key crypto.Signer, keyid string) error {
	if req.Header.Get(HeaderSignatureKey) == "" {
		return ErrMissingSigKey
	}
	hasBody := requestHasBody(req)
	if hasBody && req.Header.Get("Content-Digest") == "" {
		d, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{ContentDigestAlg})
		if err != nil {
			return fmt.Errorf("aauth: content-digest: %w", err)
		}
		req.Header.Set("Content-Digest", d)
	}
	cfg := httpsign.NewSignConfig().SignAlg(false).SignCreated(true)
	if keyid != "" {
		cfg = cfg.SetKeyID(keyid)
	}
	fields := httpsign.Headers(coveredComponents(hasBody, req.Header.Get("Content-Type") != "", hasAAuthAuthorization(req))...)
	signer, err := newHTTPSigner(key, cfg, fields)
	if err != nil {
		return err
	}
	input, sig, err := httpsign.SignRequest(DefaultSignatureLabel, *signer, req)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderSignatureInput, input)
	req.Header.Set(HeaderSignature, sig)
	return nil
}

// newHTTPSigner builds an RFC 9421 signer for key. In-memory Ed25519 and
// P-256 keys use httpsign's native signers; any other crypto.Signer (e.g. a
// hardware-backed key) goes through the JOSE signer, which produces the
// same signature bytes (RFC 9421 §3.3.7).
func newHTTPSigner(key crypto.Signer, cfg *httpsign.SignConfig, fields httpsign.Fields) (*httpsign.Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil signing key", ErrInvalidKey)
	}
	alg, err := AlgForPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return httpsign.NewEd25519Signer(k, cfg, fields)
	case *ecdsa.PrivateKey:
		return httpsign.NewP256Signer(*k, cfg, fields)
	}
	switch alg {
	case AlgEd25519:
		return httpsign.NewJWSSignerV3(jwa.EdDSA(), key, cfg, fields)
	default: // AlgES256; AlgForPublicKey admits nothing else
		return httpsign.NewJWSSignerV3(jwa.ES256(), key, cfg, fields)
	}
}

// newHTTPVerifier builds an RFC 9421 verifier for pub, an ed25519.PublicKey
// or a P-256 *ecdsa.PublicKey.
func newHTTPVerifier(pub crypto.PublicKey, cfg *httpsign.VerifyConfig, fields httpsign.Fields) (*httpsign.Verifier, error) {
	if _, err := AlgForPublicKey(pub); err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return httpsign.NewEd25519Verifier(k, cfg, fields)
	case *ecdsa.PublicKey:
		return httpsign.NewP256Verifier(*k, cfg, fields)
	}
	return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, pub)
}

// DefaultSignatureWindow is the default signature validity window for the
// created parameter (draft -11 §11.3.4 step 3; resources may advertise
// another value as signature_window).
const DefaultSignatureWindow = 60 * time.Second

// RequestVerifyOptions tunes HTTP message-signature verification.
type RequestVerifyOptions struct {
	// Window is the signature validity window for created. A signature
	// older than the window is rejected as invalid ([ErrSignatureInvalid]);
	// one further ahead of the verifier's clock than the window is rejected
	// as clock skew ([ErrClockSkew]). Zero means DefaultSignatureWindow.
	Window time.Duration
	// RequiredComponents lists covered components the server requires in
	// addition to the base set (e.g. a resource's
	// additional_signature_components).
	RequiredComponents []string
	// RequireBodyCoverage requires content-digest and content-type to be
	// covered on a request with a body. PS, AS, and revocation endpoints set
	// it (draft -11 §11.3.3.1).
	RequireBodyCoverage bool
	// Now returns the verifier's current time; nil means time.Now.
	Now func() time.Time
}

func (o RequestVerifyOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o RequestVerifyOptions) window() time.Duration {
	if o.Window > 0 {
		return o.Window
	}
	return DefaultSignatureWindow
}

// signatureInput is the parsed Signature-Input member for one label.
type signatureInput struct {
	components []string
	created    *int64
	expires    *int64
}

// parseSignatureInput parses the Signature-Input dictionary member for label
// (RFC 9421 §4.1).
func parseSignatureInput(req *http.Request, label string) (signatureInput, error) {
	var si signatureInput
	vals := req.Header.Values(HeaderSignatureInput)
	if len(vals) == 0 {
		return si, fmt.Errorf("%w: Signature-Input missing", ErrSignatureInvalid)
	}
	dict, err := httpsfv.UnmarshalDictionary(vals)
	if err != nil {
		return si, fmt.Errorf("%w: Signature-Input: %w", ErrSignatureInvalid, err)
	}
	m, ok := dict.Get(label)
	if !ok {
		return si, fmt.Errorf("%w: Signature-Input has no %q member", ErrSignatureInvalid, label)
	}
	il, ok := m.(httpsfv.InnerList)
	if !ok {
		return si, fmt.Errorf("%w: Signature-Input %q is not an inner list", ErrSignatureInvalid, label)
	}
	for _, it := range il.Items {
		name, ok := it.Value.(string)
		if !ok {
			return si, fmt.Errorf("%w: covered component is not a string", ErrSignatureInvalid)
		}
		si.components = append(si.components, name)
	}
	if il.Params != nil {
		for _, p := range []struct {
			name string
			dst  **int64
		}{{"created", &si.created}, {"expires", &si.expires}} {
			v, ok := il.Params.Get(p.name)
			if !ok {
				continue
			}
			n, ok := v.(int64)
			if !ok {
				return si, fmt.Errorf("%w: %s is not an integer", ErrSignatureInvalid, p.name)
			}
			*p.dst = &n
		}
	}
	return si, nil
}

// VerifyRequest verifies the HTTP message signature against pub (an
// ed25519.PublicKey or P-256 *ecdsa.PublicKey) with default options; see
// [VerifyRequestWithOptions].
func VerifyRequest(req *http.Request, pub crypto.PublicKey) error {
	return VerifyRequestWithOptions(req, pub, RequestVerifyOptions{})
}

// VerifyRequestWithOptions verifies the HTTP message signature on req
// against pub per draft -11 §11.3.4:
//
//  1. Signature, Signature-Input, and Signature-Key must be present
//     ([ErrSignatureInvalid]).
//  2. The covered components must include the base set, authorization
//     when an AAuth credential is sent, and any the options require
//     ([*MissingComponentsError], matching [ErrSignatureInput]).
//  3. created must be present and within the validity window: older is
//     [ErrSignatureInvalid], further ahead than the window is
//     [ErrClockSkew]. An expires in the past is [ErrSignatureInvalid].
//  4. The signature must verify under pub, whose type fixes the algorithm
//     (no alg parameter is consulted), and a Content-Digest must match the
//     body ([ErrSignatureInvalid]).
func VerifyRequestWithOptions(req *http.Request, pub crypto.PublicKey, opts RequestVerifyOptions) error {
	for _, h := range []string{HeaderSignature, HeaderSignatureInput, HeaderSignatureKey} {
		if req.Header.Get(h) == "" {
			return fmt.Errorf("%w: %s missing", ErrSignatureInvalid, h)
		}
	}
	si, err := parseSignatureInput(req, DefaultSignatureLabel)
	if err != nil {
		return err
	}

	required := coveredComponents(false, false, hasAAuthAuthorization(req))
	required = append(required, opts.RequiredComponents...)
	if opts.RequireBodyCoverage && requestHasBody(req) {
		required = append(required, "content-digest", "content-type")
	}
	if missing := missingComponents(si.components, required); len(missing) > 0 {
		return &MissingComponentsError{Required: dedupe(required), Missing: missing}
	}

	now := opts.now().Unix()
	window := int64(opts.window() / time.Second)
	switch {
	case si.created == nil:
		return fmt.Errorf("%w: created parameter missing", ErrSignatureInvalid)
	case *si.created < now-window:
		return fmt.Errorf("%w: created %d is older than the %ds window", ErrSignatureInvalid, *si.created, window)
	case *si.created > now+window:
		return fmt.Errorf("%w: created %d is %ds ahead of the verifier's clock", ErrClockSkew, *si.created, *si.created-now)
	}
	if si.expires != nil && *si.expires < now {
		return fmt.Errorf("%w: signature expired at %d", ErrSignatureInvalid, *si.expires)
	}

	// The window and expires checks above use the verifier's (injectable)
	// clock, so httpsign's own wall-clock checks are disabled.
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetRejectExpired(false)
	v, err := newHTTPVerifier(pub, cfg, httpsign.Headers(coveredComponents(false, false, hasAAuthAuthorization(req))...))
	if err != nil {
		return err
	}
	if err := httpsign.VerifyRequest(DefaultSignatureLabel, *v, req); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	if cds := req.Header.Values("Content-Digest"); len(cds) > 0 && req.Body != nil {
		if err := httpsign.ValidateContentDigestHeader(cds, &req.Body, []string{ContentDigestAlg}); err != nil {
			return fmt.Errorf("%w: content-digest: %w", ErrSignatureInvalid, err)
		}
	}
	return nil
}

// MissingComponentsError reports a Signature-Input that does not cover the
// components the verifier requires (Signature-Error invalid_input with
// required_input). It matches [ErrSignatureInput] under errors.Is.
type MissingComponentsError struct {
	Required []string // every component the verifier requires
	Missing  []string // the required components the signature omitted
}

// Error implements error.
func (e *MissingComponentsError) Error() string {
	return fmt.Sprintf("%v: missing %s", ErrSignatureInput, strings.Join(e.Missing, ", "))
}

// Is reports whether target is ErrSignatureInput.
func (e *MissingComponentsError) Is(target error) bool { return target == ErrSignatureInput }

func missingComponents(have, want []string) []string {
	set := make(map[string]bool, len(have))
	for _, c := range have {
		set[c] = true
	}
	var missing []string
	for _, c := range dedupe(want) {
		if !set[c] {
			missing = append(missing, c)
		}
	}
	return missing
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// VerifyAndExtractAgent is the server-side entry point: parse Signature-Key,
// verify the agent token (via opts.Resolver), then verify the HTTP message
// signature against the token's cnf.jwk (draft -09 §5.2.4 steps 1–5).
func VerifyAndExtractAgent(ctx context.Context, req *http.Request, opts VerifyAgentTokenOptions) (*AgentClaims, error) {
	token, err := ParseSignatureKey(req)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyAgentToken(ctx, token, opts)
	if err != nil {
		return nil, err
	}
	pub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := VerifyRequestWithOptions(req, pub, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}
