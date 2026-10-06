package aauth

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKValidate(t *testing.T) {
	good := testAgent(t).JWK()
	if good.Alg != AlgEd25519 {
		t.Fatalf("NewEd25519JWK alg = %q, want %q", good.Alg, AlgEd25519)
	}
	cases := []struct {
		name   string
		mutate func(*JWK)
		want   error
	}{
		{"valid", func(*JWK) {}, nil},
		{"alg absent", func(j *JWK) { j.Alg = "" }, ErrUnsupportedAlgorithm},
		{"polymorphic EdDSA", func(j *JWK) { j.Alg = "EdDSA" }, ErrUnsupportedAlgorithm},
		{"none", func(j *JWK) { j.Alg = "none" }, ErrUnsupportedAlgorithm},
		{"symmetric HS256", func(j *JWK) { j.Alg = "HS256" }, ErrUnsupportedAlgorithm},
		{"oct key type", func(j *JWK) { j.Kty = "oct" }, ErrUnsupportedAlgorithm},
		{"unknown alg", func(j *JWK) { j.Alg = "ML-DSA-44" }, ErrUnsupportedAlgorithm},
		{"crv disagrees with alg", func(j *JWK) { j.Crv = "X25519" }, ErrInvalidKey},
		{"kty disagrees with alg", func(j *JWK) { j.Kty = "EC" }, ErrInvalidKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := good
			c.mutate(&j)
			err := j.Validate()
			if c.want == nil {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("Validate = %v, want %v", err, c.want)
			}
			if _, err := j.PublicKey(); !errors.Is(err, c.want) {
				t.Fatalf("PublicKey = %v, want %v", err, c.want)
			}
		})
	}
}

func TestJWKPublicKeyBadX(t *testing.T) {
	j := testAgent(t).JWK()
	j.X = "AAAA"
	if _, err := j.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
	j.X = "!!"
	if _, err := j.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

func TestAgentTokenHeaderAlg(t *testing.T) {
	a := testAgent(t)
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, &AgentClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if alg := parsed.Header["alg"]; alg != AlgEd25519 {
		t.Fatalf("header alg = %v, want %q", alg, AlgEd25519)
	}

	// A token signed under the polymorphic EdDSA identifier is refused even
	// though the signature itself is valid.
	jwk := a.JWK()
	legacy := jwt.NewWithClaims(jwt.SigningMethodEdDSA, AgentClaims{DWK: WellKnownAgent, Cnf: Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{Subject: a.ID.String()}})
	legacy.Header["typ"] = TypAgent
	s, err := legacy.SignedString(a.Key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAgentToken(context.Background(), s, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestStaticResolverIgnoresUnselectedKeys(t *testing.T) {
	a := testAgent(t)
	good := a.JWK()
	// An unselected member naming a key type this verifier does not
	// implement must not prevent selecting the right one (draft -11 §11.4).
	pq := JWK{Kty: "AKP", Alg: "ML-DSA-44", Kid: "pq-1"}
	r := StaticResolver{"https://agent.example": JWKS{Keys: []JWK{pq, good}}}
	if _, err := r.ResolveKey(context.Background(), "https://agent.example", WellKnownAgent, good.Kid, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveKey(context.Background(), "https://agent.example", WellKnownAgent, "pq-1", nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
