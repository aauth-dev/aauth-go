package aauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// opaqueSigner hides the concrete key type, standing in for a
// hardware-backed crypto.Signer that never exposes private material.
type opaqueSigner struct{ inner crypto.Signer }

func (o opaqueSigner) Public() crypto.PublicKey { return o.inner.Public() }
func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.inner.Sign(r, digest, opts)
}

func TestGenerateKey(t *testing.T) {
	for _, alg := range []string{AlgEd25519, AlgES256} {
		key, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := AlgForPublicKey(key.Public())
		if err != nil || got != alg {
			t.Fatalf("AlgForPublicKey = %q, %v; want %q", got, err, alg)
		}
		j, err := NewJWK(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if j.Alg != alg || j.Kid != j.Thumbprint() {
			t.Fatalf("JWK = %+v", j)
		}
		pub, err := j.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !pub.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Fatalf("%s: JWK round trip changed the key", alg)
		}
	}
	if _, err := GenerateKey("RS256"); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestUnsupportedKeyTypes(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AlgForPublicKey(p384.Public()); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("P-384: err = %v", err)
	}
	if _, err := NewJWK(p384.Public()); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("NewJWK P-384: err = %v", err)
	}
	id, err := ParseAgentIdentifier("aauth:a@agent.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAgent(id, WithKey(p384)); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("NewAgent P-384: err = %v", err)
	}
	if _, err := NewAgent(id, WithKeyAlgorithm("PS256")); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("NewAgent PS256: err = %v", err)
	}
}

func TestDecodeP256Rejects(t *testing.T) {
	key, err := GenerateKey(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	offCurve := j
	offCurve.Y = j.X // (x, x) is not on P-256
	if _, err := offCurve.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("off-curve: err = %v", err)
	}
	short := j
	short.X = "AAAA"
	if _, err := short.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short x: err = %v", err)
	}
	wrongCrv := j
	wrongCrv.Crv = "P-384"
	if _, err := wrongCrv.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("crv/alg mismatch: err = %v", err)
	}
}

func TestECDSADERToRaw(t *testing.T) {
	if _, err := ecdsaDERToRaw([]byte{0x30, 0x00}, 32); err == nil {
		t.Fatal("empty sequence accepted")
	}
	if _, err := ecdsaDERToRaw([]byte("not der"), 32); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestAgentKeyAlgorithms runs the identity flow end to end — mint, verify
// token, sign request, verify request — for each algorithm, with both an
// in-memory key and an opaque crypto.Signer.
func TestAgentKeyAlgorithms(t *testing.T) {
	for _, alg := range []string{AlgEd25519, AlgES256} {
		for _, opaque := range []bool{false, true} {
			name := alg
			if opaque {
				name += "/opaque"
			}
			t.Run(name, func(t *testing.T) {
				key, err := GenerateKey(alg)
				if err != nil {
					t.Fatal(err)
				}
				if opaque {
					key = opaqueSigner{key}
				}
				a := testAgent(t, WithKey(key))
				tok, err := a.MintToken()
				if err != nil {
					t.Fatal(err)
				}
				parsed, _, err := jwt.NewParser().ParseUnverified(tok, &AgentClaims{})
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Header["alg"] != alg {
					t.Fatalf("header alg = %v, want %s", parsed.Header["alg"], alg)
				}

				req, err := http.NewRequest(http.MethodPost, "https://resource.example/api", nil)
				if err != nil {
					t.Fatal(err)
				}
				setBody(req, `{"x":1}`)
				AttachSignatureKey(req, tok)
				if err := SignRequest(req, a.Key, ""); err != nil {
					t.Fatal(err)
				}
				setBody(req, `{"x":1}`)
				claims, err := VerifyAndExtractAgent(context.Background(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
				if err != nil {
					t.Fatal(err)
				}
				if claims.Cnf.JWK.Alg != alg {
					t.Fatalf("cnf.jwk alg = %q", claims.Cnf.JWK.Alg)
				}
			})
		}
	}
}

func TestJWSAlgMustMatchKey(t *testing.T) {
	ed := testAgent(t)
	es := testAgent(t, WithKeyAlgorithm(AlgES256))
	tok, err := es.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	// An ES256 token cannot verify under an Ed25519 key.
	r := StaticResolver{"": JWKS{Keys: []JWK{ed.JWK()}}}
	if _, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: r}); err == nil {
		t.Fatal("ES256 token verified under an Ed25519 key")
	}
}

// One key has one accepted encoding: alternate base64url encodings of x or
// y (non-zero trailing bits, embedded line breaks) are refused, and do not
// change the thumbprint.
func TestJWKAlternateEncodings(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// flipTrailingBits sets the unused low bit of the last character.
	flipTrailingBits := func(s string) string {
		i := strings.IndexByte(alphabet, s[len(s)-1])
		return s[:len(s)-1] + string(alphabet[i|1])
	}
	for _, alg := range []string{AlgEd25519, AlgES256} {
		key, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		j, err := NewJWK(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		want := j.Thumbprint()
		variants := []func(JWK) JWK{
			func(v JWK) JWK { v.X = flipTrailingBits(v.X); return v },
			func(v JWK) JWK { v.X = v.X[:10] + "\n" + v.X[10:]; return v },
			func(v JWK) JWK { v.X = v.X[:10] + "\r\n" + v.X[10:]; return v },
		}
		if alg == AlgES256 {
			variants = append(variants,
				func(v JWK) JWK { v.Y = flipTrailingBits(v.Y); return v },
				func(v JWK) JWK { v.Y = v.Y + "\n"; return v },
			)
		}
		for i, mutate := range variants {
			v := mutate(j)
			if v.X == j.X && v.Y == j.Y {
				t.Fatalf("%s variant %d: no change", alg, i)
			}
			if _, err := v.PublicKey(); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("%s variant %d: PublicKey err = %v, want ErrInvalidKey", alg, i, err)
			}
			if got := v.Thumbprint(); got != want {
				t.Errorf("%s variant %d: thumbprint %s, want %s", alg, i, got, want)
			}
		}
		if _, err := j.PublicKey(); err != nil {
			t.Fatalf("%s canonical: %v", alg, err)
		}
	}
}
