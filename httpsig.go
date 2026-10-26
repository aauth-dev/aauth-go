package aauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
// [SignRequest] also covers @query when the URL has a query, so the query
// cannot be changed in transit; verifiers do not require it unless asked
// to (RequestVerifyOptions.RequiredComponents).
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

// requestHasBody reports whether an incoming request carries content, for
// verification: a server restoring a body it already read leaves
// ContentLength zero, and an incoming request with no body has http.NoBody.
func requestHasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

// MaxSignedStreamBytes bounds how much of a request body of unknown length
// [SignRequest] buffers to compute its digest (4 MiB, as for
// [Transport.MaxBodyBytes]).
const MaxSignedStreamBytes = 4 << 20

// bufferStreamingBody reads an outgoing body of unknown length (a non-nil
// body with ContentLength zero or -1) into memory, so its digest can be signed and
// its length is known when sent. An empty body becomes http.NoBody.
//
// At most MaxSignedStreamBytes are buffered; a longer body is an error
// rather than unbounded memory. A caller with a larger body computes its
// Content-Digest itself and sets the header, in which case the body is not
// read here.
func bufferStreamingBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength > 0 || req.Header.Get("Content-Digest") != "" {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, MaxSignedStreamBytes+1))
	cerr := req.Body.Close()
	if err != nil {
		return fmt.Errorf("aauth: read request body: %w", err)
	}
	if len(b) > MaxSignedStreamBytes {
		return fmt.Errorf("aauth: request body of unknown length exceeds %d bytes; set ContentLength, or set Content-Digest yourself", MaxSignedStreamBytes)
	}
	if cerr != nil {
		return fmt.Errorf("aauth: close request body: %w", cerr)
	}
	if len(b) == 0 {
		req.Body, req.GetBody = http.NoBody, nil
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	req.ContentLength = int64(len(b))
	return nil
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

// UnsupportedSchemeError reports a Signature-Key scheme the verifier does
// not accept for this request, with the schemes it does accept (sent as
// Accept-Signature-Scheme). It matches [ErrUnsupportedScheme].
type UnsupportedSchemeError struct {
	Scheme   string   // the scheme presented
	Accepted []string // the schemes the verifier accepts here
}

// Error implements error.
func (e *UnsupportedSchemeError) Error() string {
	return fmt.Sprintf("%v: %q (accepted: %s)", ErrUnsupportedScheme, e.Scheme, strings.Join(e.Accepted, ", "))
}

// Is reports whether target is ErrUnsupportedScheme.
func (e *UnsupportedSchemeError) Is(target error) bool { return target == ErrUnsupportedScheme }

// ParseSignatureKey returns the JWT carried under the jwt scheme for the
// default label. Any other scheme is [ErrUnsupportedScheme] (draft -11
// §11.3.4 step 4: agents MUST use the jwt scheme).
func ParseSignatureKey(req *http.Request) (string, error) {
	sk, err := ParseSignatureKeyMember(req, DefaultSignatureLabel)
	if err != nil {
		return "", err
	}
	if sk.Scheme != SchemeJWT {
		return "", &UnsupportedSchemeError{Scheme: sk.Scheme, Accepted: []string{SchemeJWT}}
	}
	tok := sk.Params["jwt"]
	if tok == "" {
		return "", fmt.Errorf("%w: jwt scheme without a jwt parameter", ErrBadSigKey)
	}
	return tok, nil
}

// SignRequest signs req per the AAuth profile: sets Content-Digest when a
// body is present, then Signature-Input and Signature under the default
// label, with created set to the current time. It covers the AAuth
// components (see the profile above), plus @query when the URL has a
// query. The Signature-Key header
// MUST already be attached (it is a covered component). key may be any
// supported crypto.Signer (see [GenerateKey]); the algorithm is determined
// by the key and never sent on the wire (draft -11 §11.3.3.2).
//
// keyid SHOULD be empty: draft -11 §11.3.3.2 says agents SHOULD NOT send the
// keyid parameter, since Signature-Key identifies the key. A non-empty value
// is emitted as given (it MUST then identify the same key).
func SignRequest(req *http.Request, key crypto.Signer, keyid string) error {
	return SignRequestCovering(req, key, keyid, nil)
}

// SignRequestCovering is [SignRequest], covering the extra components as
// well: for example a resource's additional_signature_components, or the
// required_input of an invalid_input Signature-Error (draft -11 §11.3.3.1).
// A component already covered is not repeated.
func SignRequestCovering(req *http.Request, key crypto.Signer, keyid string, extra []string) error {
	if req.Header.Get(HeaderSignatureKey) == "" {
		return ErrMissingSigKey
	}
	if req.URL != nil && req.URL.Path == "" && req.URL.Opaque == "" {
		// An empty path is sent, and its @path derived, as "/" (RFC 9421
		// §2.2.6); sign what the recipient will see.
		req.URL.Path = "/"
	}
	// A body of unknown length is buffered so it is covered by a digest
	// rather than signed as if absent.
	if err := bufferStreamingBody(req); err != nil {
		return err
	}
	// Any body left now is sent, whatever ContentLength says: a streaming
	// body whose digest the caller supplied is still covered.
	hasBody := req.Body != nil && req.Body != http.NoBody
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
	components := coveredComponents(hasBody, req.Header.Get("Content-Type") != "", hasAAuthAuthorization(req))
	if req.URL != nil && req.URL.RawQuery != "" {
		components = append(components, "@query")
	}
	components = dedupe(append(components, extra...))
	signer, err := newHTTPSigner(key, cfg, httpsign.Headers(components...))
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
	// Authority is the verifier's own host, with a port only when it is not
	// the scheme's default, as the signer covers it in @authority. When set,
	// a signature whose @authority names another host is refused
	// ([ErrWrongAuthority]), so a request signed for one server cannot be
	// replayed to another. Servers set it from their identifier with
	// [AuthorityOf].
	Authority string
	// MaxBodySize bounds how much of a request body verification reads to
	// check its Content-Digest. A larger body is refused with
	// [ErrBodyTooLarge] before it is read in full. Zero means
	// DefaultMaxVerifyBodyBytes; a negative value means no limit.
	MaxBodySize int64
}

// DefaultMaxVerifyBodyBytes is the default [RequestVerifyOptions.MaxBodySize]
// (4 MiB, the most [SignRequest] buffers for a body of unknown length).
const DefaultMaxVerifyBodyBytes = MaxSignedStreamBytes

// ErrBodyTooLarge means a signed request body exceeds
// [RequestVerifyOptions.MaxBodySize]. It is classified as the
// Signature-Error invalid_request.
var ErrBodyTooLarge = errors.New("aauth: request body too large to verify")

func (o RequestVerifyOptions) maxBodySize() int64 {
	switch {
	case o.MaxBodySize > 0:
		return o.MaxBodySize
	case o.MaxBodySize < 0:
		return 0 // httpsign: no limit
	}
	return DefaultMaxVerifyBodyBytes
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
	components []string // covered component names, with or without parameters
	plain      []string // covered components that carry no parameters
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
		if it.Params == nil || len(it.Params.Names()) == 0 {
			si.plain = append(si.plain, name)
			continue
		}
		// AAuth never covers trailers (tr) or the request of a response
		// (req). Either would make verification read the whole body
		// before checking the signature, so they are refused here.
		for _, p := range []string{"tr", "req"} {
			if _, has := it.Params.Get(p); has {
				return si, fmt.Errorf("%w: covered component %q has the %s parameter", ErrSignatureInvalid, name, p)
			}
		}
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
//     ([*MissingComponentsError], matching [ErrSignatureInput]). Only a
//     component without parameters counts: "signature-key";key="other"
//     does not cover signature-key. A component with the tr or req
//     parameter is refused ([ErrSignatureInvalid]).
//  3. created must be present and within the validity window: older is
//     [ErrSignatureInvalid], further ahead than the window is
//     [ErrClockSkew]. An expires in the past is [ErrSignatureInvalid].
//  4. The signature must verify under pub, whose type fixes the algorithm
//     (no alg parameter is consulted), and a Content-Digest must match the
//     body ([ErrSignatureInvalid]). A body larger than opts.MaxBodySize is
//     [ErrBodyTooLarge].
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

	if opts.Authority != "" && !strings.EqualFold(normalizeAuthority(req.Host), normalizeAuthority(opts.Authority)) {
		return fmt.Errorf("%w: @authority %q is not %q", ErrWrongAuthority, req.Host, opts.Authority)
	}

	required := coveredComponents(false, false, hasAAuthAuthorization(req))
	required = append(required, opts.RequiredComponents...)
	if opts.RequireBodyCoverage && requestHasBody(req) {
		required = append(required, "content-digest", "content-type")
	}
	if missing := missingComponents(si.plain, required); len(missing) > 0 {
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
	limit := opts.maxBodySize()
	if limit > 0 && req.ContentLength > limit {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrBodyTooLarge, req.ContentLength, limit)
	}
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetRejectExpired(false).SetMaxBodySize(limit)
	v, err := newHTTPVerifier(pub, cfg, httpsign.Headers(coveredComponents(false, false, hasAAuthAuthorization(req))...))
	if err != nil {
		return err
	}
	if err := httpsign.VerifyRequest(DefaultSignatureLabel, *v, req); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrSignatureInvalid, errSignatureMismatch, err)
	}
	if cds := req.Header.Values("Content-Digest"); len(cds) > 0 && req.Body != nil {
		if err := bufferVerifiedBody(req, limit); err != nil {
			return err
		}
		if err := httpsign.ValidateContentDigestHeader(cds, &req.Body, []string{ContentDigestAlg}, httpsign.NewDigestOptions().SetMaxBodySize(limit)); err != nil {
			return fmt.Errorf("%w: content-digest: %w", ErrSignatureInvalid, err)
		}
	}
	return nil
}

// bufferVerifiedBody reads req's body into memory, up to limit bytes (zero
// means no limit), so its digest can be checked; a longer body is
// [ErrBodyTooLarge]. The body is replaced with the bytes read.
func bufferVerifiedBody(req *http.Request, limit int64) error {
	r := io.Reader(req.Body)
	if limit > 0 {
		r = io.LimitReader(req.Body, limit+1)
	}
	b, err := io.ReadAll(r)
	cerr := req.Body.Close()
	if err != nil {
		return fmt.Errorf("aauth: read request body: %w", err)
	}
	if limit > 0 && int64(len(b)) > limit {
		return fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, limit)
	}
	if cerr != nil {
		return fmt.Errorf("aauth: close request body: %w", cerr)
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	return nil
}

// ErrWrongAuthority reports a signature whose @authority is not the
// verifier's own host (RFC 9421 §2.2.3). It matches [ErrSignatureInvalid].
var ErrWrongAuthority = fmt.Errorf("%w: wrong @authority", ErrSignatureInvalid)

// AuthorityOf returns the @authority a request to a server with the given
// identifier carries: its host, with the port only when it is not the
// scheme's default.
func AuthorityOf(identifier string) (string, error) {
	u, err := url.Parse(identifier)
	if err != nil {
		return "", fmt.Errorf("aauth: authority of %q: %w", identifier, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("aauth: authority of %q: no host", identifier)
	}
	return normalizeAuthority(u.Host), nil
}

// normalizeAuthority lowercases host and drops a default port (443 or 80),
// which RFC 9421 §2.2.3 omits from @authority. Dropping either keeps the
// comparison working behind a proxy that terminates TLS, where the request
// the verifier sees is plain http.
func normalizeAuthority(host string) string {
	host = strings.ToLower(host)
	if h, port, err := net.SplitHostPort(host); err == nil {
		if port == "443" || port == "80" {
			if strings.Contains(h, ":") {
				return "[" + h + "]"
			}
			return h
		}
	}
	return host
}

// errSignatureMismatch marks a failure of the RFC 9421 cryptographic check.
var errSignatureMismatch = errors.New("signature does not verify")

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
// signature against the token's cnf.jwk (draft -11 §5.3.3).
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
