package aauth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSubAgentDiscriminatorValidation(t *testing.T) {
	parent, err := ParseAgentIdentifier("aauth:planner.7f3c@vendor.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "a+b", "has space", "ünï", strings.Repeat("x", MaxAgentLocalPartLength)} {
		if _, err := parent.SubAgent(bad); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("discriminator %q: err = %v, want ErrInvalidIdentifier", bad, err)
		}
	}
	sub, err := parent.SubAgent("search1")
	if err != nil {
		t.Fatal(err)
	}
	if sub.String() != "aauth:planner.7f3c+search1@vendor.example" {
		t.Fatalf("sub = %s", sub)
	}
	// Identifiers compare exactly: case is significant in the local part.
	upper, err := ParseAgentIdentifier("aauth:Planner.7f3c@vendor.example")
	if err != nil {
		t.Fatal(err)
	}
	if upper == parent {
		t.Fatal("identifiers differing in case compared equal")
	}
}

func TestRequireProviderClaimsServerIdentifiers(t *testing.T) {
	ctx := context.Background()
	strict := VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}, RequireProviderClaims: true}
	for _, c := range []struct {
		name   string
		issuer string
		ps     string
		ok     bool
	}{
		{"conforming", "https://agent.example", "https://ps.example", true},
		{"no ps", "https://agent.example", "", true},
		{"iss with port", "https://agent.example:8443", "", false},
		{"iss with trailing slash", "https://agent.example/", "", false},
		{"iss uppercase", "https://Agent.Example", "", false},
		{"iss http", "http://agent.example", "", false},
		{"ps with path", "https://agent.example", "https://ps.example/v1", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := testAgent(t, WithIssuer(c.issuer), WithPersonServer(c.ps))
			tok, err := a.MintToken()
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyAgentToken(ctx, tok, strict)
			if c.ok && err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !c.ok {
				if !errors.Is(err, ErrInvalidIdentifier) {
					t.Fatalf("err = %v, want ErrInvalidIdentifier", err)
				}
				if se, ok := SignatureErrorFor(err); !ok || se.Code != SigErrInvalidJWT {
					t.Fatalf("Signature-Error = %q, want invalid_jwt", se.Code)
				}
				// Relaxed (local) mode does not check provider claims.
				if _, err := VerifyAgentToken(ctx, tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
					t.Fatalf("relaxed: %v", err)
				}
			}
		})
	}
}
