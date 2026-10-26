package accessserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// An access server's metadata cannot send the PS's signed token request
// to another origin.
func TestClientRefusesCrossOriginTokenEndpoint(t *testing.T) {
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, aauth.AccessServerMetadata{ServerMetadata: aauth.ServerMetadata{Issuer: url, JWKSURI: url + "/jwks"},
			AuthTokenEndpoint: "https://elsewhere.example/token"})
	}))
	t.Cleanup(srv.Close)
	url = srv.URL
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(aauth.ServerSigner{Issuer: "https://ps.example", DWK: aauth.WellKnownPerson, Key: key}, http.DefaultClient)
	_, err = c.Federate(context.Background(), &personserver.FederationRequest{AccessServer: url})
	if err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("cross-origin endpoint: %v", err)
	}
}
