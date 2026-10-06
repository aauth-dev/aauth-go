package aauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/yaronf/httpsign"
)

// The AAuth HTTP message-signature profile (draft -09 §12.7): every request
// is signed with the key from cnf.jwk, covering exactly the four mandated
// components (each closes a request-substitution attack):
//
//	@method, @authority, @path, signature-key
//
// content-digest is added when the request has a body — permitted as an
// additional component (resources advertise extras via
// additional_signature_components in their metadata).
// When the request carries an opaque access token (`Authorization: AAuth …`,
// §6.4), the authorization header is additionally covered — binding the
// token to the signature so it can't be replayed as a bearer credential.
func coveredFields(hasBody, hasAAuthAccess bool) httpsign.Fields {
	base := []string{"@method", "@authority", "@path", "signature-key"}
	if hasAAuthAccess {
		base = append(base, "authorization")
	}
	if hasBody {
		base = append(base, "content-digest")
	}
	return httpsign.Headers(base...)
}

// hasAAuthAuthorization reports whether the request carries an
// `Authorization: AAuth <token68>` credential.
func hasAAuthAuthorization(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "AAuth ")
}

// ContentDigestAlg is the digest algorithm for the Content-Digest header.
const ContentDigestAlg = "sha-256"

// AttachSignatureKey sets the Signature-Key header carrying the agent (or
// auth) token via scheme=jwt (signature-key draft §3.6). The dictionary key
// is the signature label (§3: labels correlate across Signature-Input,
// Signature, and Signature-Key).
func AttachSignatureKey(req *http.Request, token string) {
	req.Header.Set(HeaderSignatureKey, fmt.Sprintf(`%s=jwt; jwt=%q`, DefaultSignatureLabel, token))
}

// ParseSignatureKey extracts the scheme=jwt token for the default label.
func ParseSignatureKey(req *http.Request) (string, error) {
	h := req.Header.Get(HeaderSignatureKey)
	if h == "" {
		return "", ErrMissingSigKey
	}
	// Structured-field dictionary member: <label>=jwt;jwt="<token>".
	// Accept whitespace variance between parameters.
	idx := strings.Index(h, DefaultSignatureLabel+"=jwt")
	if idx < 0 {
		return "", ErrBadSigKey
	}
	rest := h[idx:]
	jidx := strings.Index(rest, `jwt="`)
	if jidx < 0 {
		return "", ErrBadSigKey
	}
	rest = rest[jidx+len(`jwt="`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", ErrBadSigKey
	}
	if rest[:end] == "" {
		return "", ErrBadSigKey
	}
	return rest[:end], nil
}

// SignRequest signs req per the AAuth profile: sets Content-Digest when a
// body is present, then Signature-Input and Signature under the default
// label. The Signature-Key header MUST already be attached (it is a covered
// component). key may be any supported crypto.Signer (see [GenerateKey]);
// the algorithm is determined by the key, never sent on the wire (draft -11
// §11.3.3.2). keyid is set to the given value when non-empty.
func SignRequest(req *http.Request, key crypto.Signer, keyid string) error {
	if req.Header.Get(HeaderSignatureKey) == "" {
		return ErrMissingSigKey
	}
	hasBody := req.Body != nil && req.ContentLength != 0
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
	signer, err := newHTTPSigner(key, cfg, coveredFields(hasBody, hasAAuthAuthorization(req)))
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

// VerifyRequest verifies the HTTP message signature against pub (an
// ed25519.PublicKey or P-256 *ecdsa.PublicKey), requiring the mandated
// component coverage.
func VerifyRequest(req *http.Request, pub crypto.PublicKey) error {
	// No SetAllowedAlgs: AAuth derives the algorithm from the key's JWK alg
	// (draft -11 §11.3.1) rather than a signed alg parameter; the verifier
	// construction below pins the algorithm to the key type.
	// If the request carries Authorization: AAuth, that header MUST be a
	// covered component (§6.4) — required symmetrically here.
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false)
	v, err := newHTTPVerifier(pub, cfg, coveredFields(false, hasAAuthAuthorization(req)))
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
	if err := VerifyRequest(req, pub); err != nil {
		return nil, err
	}
	return claims, nil
}
