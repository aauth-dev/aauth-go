package aauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Signing keys are crypto.Signer values so that keys held in a platform
// keystore or secure enclave (which never expose private material) work the
// same as in-memory keys. Two algorithms are implemented (draft -11
// §11.3.1): Ed25519 (MUST) and ES256 (SHOULD; ECDSA on P-256 with SHA-256,
// the usual choice for hardware-backed keys).
//
// Supported key types:
//
//   - Ed25519: ed25519.PrivateKey, or any crypto.Signer whose Public() is an
//     ed25519.PublicKey.
//   - ES256: *ecdsa.PrivateKey on P-256, or any crypto.Signer whose Public()
//     is a P-256 *ecdsa.PublicKey (signing ASN.1 DER over a SHA-256 digest,
//     as crypto.Signer implementations do).
//
// Public keys are crypto.PublicKey values: ed25519.PublicKey or
// *ecdsa.PublicKey.

// GenerateKey creates a fresh in-memory signing key for alg ([AlgEd25519]
// or [AlgES256]).
func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case AlgEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
}

// AlgForPublicKey returns the fully-specified algorithm a public key is
// used with: [AlgEd25519] for an ed25519.PublicKey, [AlgES256] for a P-256
// *ecdsa.PublicKey. Other keys yield [ErrUnsupportedAlgorithm].
func AlgForPublicKey(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: Ed25519 public key has length %d", ErrInvalidKey, len(k))
		}
		return AlgEd25519, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return "", fmt.Errorf("%w: only P-256 ECDSA keys are supported", ErrUnsupportedAlgorithm)
		}
		return AlgES256, nil
	}
	return "", fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, pub)
}

// signJOSE produces the JOSE signature (RFC 7518 §3.4 / RFC 8037) over msg
// with key under alg: raw Ed25519 bytes, or the fixed-length r||s encoding
// for ES256. The same bytes serve as a JWS signature and as an RFC 9421
// signature under the JOSE algorithms (RFC 9421 §3.3.7).
func signJOSE(key crypto.Signer, alg string, msg []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil signing key", ErrInvalidKey)
	}
	keyAlg, err := AlgForPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if keyAlg != alg {
		return nil, fmt.Errorf("%w: %s key cannot sign %s", ErrInvalidKey, keyAlg, alg)
	}
	switch alg {
	case AlgEd25519:
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	case AlgES256:
		digest := sha256.Sum256(msg)
		der, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return ecdsaDERToRaw(der, 32)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
}

// ecdsaDERToRaw converts an ASN.1 DER ECDSA signature to the fixed-length
// r||s form JOSE uses.
func ecdsaDERToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("aauth: ECDSA signature: %w", err)
	}
	if len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, fmt.Errorf("aauth: malformed ECDSA signature")
	}
	if len(sig.R.Bytes()) > size || len(sig.S.Bytes()) > size {
		return nil, fmt.Errorf("aauth: ECDSA signature component too large")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// NewJWK builds the public JWK for pub (an ed25519.PublicKey or a P-256
// *ecdsa.PublicKey) with its fully-specified alg, use "sig", and Kid set to
// the RFC 7638 thumbprint.
func NewJWK(pub crypto.PublicKey) (JWK, error) {
	alg, err := AlgForPublicKey(pub)
	if err != nil {
		return JWK{}, err
	}
	var j JWK
	switch alg {
	case AlgEd25519:
		return NewEd25519JWK(pub.(ed25519.PublicKey)), nil
	case AlgES256:
		ek, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return JWK{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		raw := ek.Bytes() // 0x04 || X (32) || Y (32)
		j = JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
			Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
			Alg: AlgES256,
			Use: "sig",
		}
	}
	j.Kid = j.Thumbprint()
	return j, nil
}

// decodeP256 decodes and validates (on-curve) the x/y coordinates of a
// P-256 JWK.
func decodeP256(x, y string) (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("%w: JWK x decode: %w", ErrInvalidKey, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("%w: JWK y decode: %w", ErrInvalidKey, err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates must be 32 bytes", ErrInvalidKey)
	}
	uncompressed := append(append([]byte{4}, xb...), yb...)
	// ParseUncompressedPublicKey rejects points not on the curve.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return pub, nil
}

// verifyJOSE verifies a JOSE-encoded signature (see signJOSE) over msg.
func verifyJOSE(pub crypto.PublicKey, msg, sig []byte) error {
	alg, err := AlgForPublicKey(pub)
	if err != nil {
		return err
	}
	switch alg {
	case AlgEd25519:
		if !ed25519.Verify(pub.(ed25519.PublicKey), msg, sig) {
			return ErrSignatureInvalid
		}
		return nil
	case AlgES256:
		if len(sig) != 64 {
			return fmt.Errorf("%w: ES256 signature length %d", ErrSignatureInvalid, len(sig))
		}
		digest := sha256.Sum256(msg)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), digest[:], r, s) {
			return ErrSignatureInvalid
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
}
