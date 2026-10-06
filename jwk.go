package aauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// JWK is a minimal JSON Web Key. Ed25519 OKP keys are the AAuth baseline
// (draft -11 §11.3.1: Ed25519 MUST; ES256 SHOULD). Every key AAuth conveys
// or references MUST carry a fully-specified alg (signature-key §3.3);
// [JWK.Validate] enforces this.
type JWK struct {
	Kty string `json:"kty"`           // key type; "OKP" (Ed25519) or "EC" (P-256)
	Crv string `json:"crv,omitempty"` // curve; "Ed25519" or "P-256"
	X   string `json:"x,omitempty"`   // base64url public key (OKP) or x coordinate (EC)
	Y   string `json:"y,omitempty"`   // base64url y coordinate (EC only)
	Kid string `json:"kid,omitempty"` // key id; the RFC 7638 thumbprint
	Alg string `json:"alg,omitempty"` // fully-specified algorithm; "Ed25519" or "ES256"
	Use string `json:"use,omitempty"` // intended use; "sig"
}

// JWKS is a JSON Web Key Set, served at the URL published as jwks_uri in a
// well-known metadata document.
type JWKS struct {
	Keys []JWK `json:"keys"` // the key set
}

// NewEd25519JWK builds a JWK from an Ed25519 public key with Kid set to the
// RFC 7638 thumbprint.
func NewEd25519JWK(pub ed25519.PublicKey) JWK {
	j := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: AlgEd25519,
		Use: "sig",
	}
	j.Kid = j.Thumbprint()
	return j
}

// Thumbprint computes the RFC 7638 thumbprint over the required members in
// lexicographic order with no whitespace — crv, kty, x for OKP (RFC 8037
// §2); crv, kty, x, y for EC (RFC 7638 §3.2) — base64url-encoded.
func (j JWK) Thumbprint() string {
	var canonical string
	if j.Kty == "EC" {
		canonical = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	} else {
		canonical = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, j.Crv, j.Kty, j.X)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Validate applies the Algorithm Determination rules (signature-key §3.3;
// draft -11 §11.3.1): alg MUST be present and fully specified — the
// polymorphic "EdDSA", "none", and symmetric algorithms are rejected with
// [ErrUnsupportedAlgorithm] — and kty/crv MUST agree with alg, else
// [ErrInvalidKey].
func (j JWK) Validate() error { return validateKeyAlg(j) }

// PublicKey validates the JWK (see [JWK.Validate]) and decodes it to a
// crypto.PublicKey: an ed25519.PublicKey for alg Ed25519, or a P-256
// *ecdsa.PublicKey for alg ES256. Decoding failures, including an EC point
// not on the curve, are [ErrInvalidKey].
func (j JWK) PublicKey() (crypto.PublicKey, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	switch j.Alg {
	case AlgES256:
		return decodeP256(j.X, j.Y)
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: JWK x decode: %w", ErrInvalidKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: JWK x has wrong length for Ed25519", ErrInvalidKey)
	}
	return ed25519.PublicKey(raw), nil
}

// Cnf is the JWT confirmation claim (RFC 7800). Agent tokens carry the full
// public key in JWK; other token types may bind by thumbprint via JKT.
type Cnf struct {
	JWK *JWK   `json:"jwk,omitempty"` // the confirmation public key
	JKT string `json:"jkt,omitempty"` // RFC 7638 thumbprint (alternative to JWK)
}
