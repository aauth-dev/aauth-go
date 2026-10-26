package agentprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/golang-jwt/jwt/v5"
)

// Enroll refuses an agent token whose iss is not the provider it asked.
func TestEnrollChecksIssuer(t *testing.T) {
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	other, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := aauth.MintAgentToken(aauth.AgentClaims{DWK: aauth.WellKnownAgent, Cnf: aauth.Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://other.example", Subject: "aauth:a@other.example", ID: "j",
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}}, other, "k")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, TokenResponse{AgentToken: tok, ExpiresIn: 3600})
	}))
	t.Cleanup(srv.Close)
	if _, err := (&Client{BaseURL: srv.URL}).Enroll(context.Background(), key, nil); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
}
