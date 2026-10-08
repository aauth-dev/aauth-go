package aauth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Fully-specified JOSE signature algorithm identifiers (draft -11 §11.3.1;
// RFC 9864). AAuth names an algorithm only by a fully-specified identifier,
// carried in the alg member of every JWK and in every JWS header.
const (
	// AlgEd25519 is EdDSA over Ed25519 (RFC 9864). Every party MUST
	// support it.
	AlgEd25519 = "Ed25519"
	// AlgES256 is ECDSA on P-256 with SHA-256 (RFC 7518). Every party
	// SHOULD support it; it suits hardware-backed keys.
	AlgES256 = "ES256"
)

// algEdDSA is the polymorphic identifier that draft -11 §11.3.1 and
// signature-key §3.3 forbid; it is recognized only to be rejected.
const algEdDSA = "EdDSA"

// Errors classifying key and algorithm failures (signature-key §3.3). They
// map onto the Signature-Error codes unsupported_algorithm and invalid_key.
var (
	// ErrUnsupportedAlgorithm means a key's alg is absent, polymorphic
	// (EdDSA), prohibited (none, symmetric), or not implemented.
	ErrUnsupportedAlgorithm = errors.New("aauth: unsupported algorithm")
	// ErrInvalidKey means a key could not be parsed, or its kty/crv
	// disagree with its alg.
	ErrInvalidKey = errors.New("aauth: invalid key")
)

// SigningMethodEd25519 is the golang-jwt signing method for the
// fully-specified "Ed25519" JWS algorithm. It is registered with golang-jwt
// under that name. Signing accepts an ed25519.PrivateKey or any
// crypto.Signer whose public key is Ed25519; verification takes an
// ed25519.PublicKey.
var SigningMethodEd25519 jwt.SigningMethod = signingMethodEd25519{}

// signingMethodEd25519 reuses golang-jwt's EdDSA primitive (the signature
// operation is identical) under the fully-specified identifier.
type signingMethodEd25519 struct{}

func (signingMethodEd25519) Alg() string { return AlgEd25519 }

func (signingMethodEd25519) Sign(signingString string, key any) ([]byte, error) {
	return jwt.SigningMethodEdDSA.Sign(signingString, key)
}

func (signingMethodEd25519) Verify(signingString string, sig []byte, key any) error {
	return jwt.SigningMethodEdDSA.Verify(signingString, sig, key)
}

func init() {
	jwt.RegisterSigningMethod(AlgEd25519, func() jwt.SigningMethod { return SigningMethodEd25519 })
}

// acceptedJWSAlgs is the set of JWS algorithms this implementation verifies.
func acceptedJWSAlgs() []string { return []string{AlgEd25519, AlgES256} }

// jwtMethodFor returns the golang-jwt signing method for alg. It is used
// for the JWS header and for verification; signing goes through signJOSE so
// that any crypto.Signer works.
func jwtMethodFor(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case AlgEd25519:
		return SigningMethodEd25519, nil
	case AlgES256:
		return jwt.SigningMethodES256, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
}

// newJWTParser returns a parser pinned to the accepted fully-specified
// algorithms (draft -11 §11.5.1: none, EdDSA, and symmetric algorithms are
// never accepted).
func newJWTParser(opts ...jwt.ParserOption) *jwt.Parser {
	return jwt.NewParser(append([]jwt.ParserOption{jwt.WithValidMethods(acceptedJWSAlgs())}, opts...)...)
}

// checkJWSHeaderAlg rejects a JWS whose header alg is absent or not one of
// the accepted fully-specified identifiers, before any key is resolved.
func checkJWSHeaderAlg(tok *jwt.Token) error {
	alg, _ := tok.Header["alg"].(string)
	for _, a := range acceptedJWSAlgs() {
		if alg == a {
			return nil
		}
	}
	if alg == "" {
		return fmt.Errorf("%w: JWS header alg missing", ErrInvalidToken)
	}
	return fmt.Errorf("%w: JWS header alg %q not accepted", ErrInvalidToken, alg)
}

// keyTypeForAlg is the (kty, crv) a fully-specified algorithm determines.
type keyTypeForAlg struct{ kty, crv string }

var algKeyTypes = map[string]keyTypeForAlg{
	AlgEd25519: {kty: "OKP", crv: "Ed25519"},
	AlgES256:   {kty: "EC", crv: "P-256"},
}

// validateKeyAlg applies signature-key §3.3 Algorithm Determination to a
// JWK: alg MUST be present and fully specified, MUST NOT be prohibited, and
// kty/crv MUST agree with it.
func validateKeyAlg(j JWK) error {
	switch {
	case j.Alg == "":
		return fmt.Errorf("%w: JWK alg is absent", ErrUnsupportedAlgorithm)
	case j.Alg == algEdDSA:
		return fmt.Errorf("%w: polymorphic alg %q (use %q)", ErrUnsupportedAlgorithm, j.Alg, AlgEd25519)
	case j.Kty == "oct" || j.Alg == "none" || j.Alg == "HS256" || j.Alg == "HS384" || j.Alg == "HS512":
		return fmt.Errorf("%w: prohibited or symmetric alg %q (kty %q)", ErrUnsupportedAlgorithm, j.Alg, j.Kty)
	}
	want, ok := algKeyTypes[j.Alg]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, j.Alg)
	}
	// crv is REQUIRED for OKP (RFC 8037 §2) and EC (RFC 7518 §6.2.1.1)
	// keys, so a missing crv disagrees with alg like a wrong one.
	if j.Kty != want.kty || j.Crv != want.crv {
		return fmt.Errorf("%w: kty=%q crv=%q disagree with alg %q", ErrInvalidKey, j.Kty, j.Crv, j.Alg)
	}
	return nil
}
