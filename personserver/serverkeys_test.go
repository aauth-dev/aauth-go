package personserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// The PS keeps one resolver for revocation callers' keys, so the JWKS a
// caller publishes is fetched once and cached across requests.
func TestRevocationKeysCachedAcrossRequests(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	var fetches atomic.Int32
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/" + aauth.WellKnownResource:
			writeJSON(rw, http.StatusOK, map[string]string{"issuer": url, "jwks_uri": url + "/jwks"})
		case "/jwks":
			fetches.Add(1)
			writeJSON(rw, http.StatusOK, w.resKey.JWKS())
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(srv.Close)
	url = srv.URL
	rev := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: aauth.ServerSigner{
		Issuer: url, DWK: aauth.WellKnownResource, Kid: w.resKey.JWK().Kid, Key: w.resKey.Key}}
	for _, jti := range []string{"one", "two", "three"} {
		if _, err := rev.Revoke(ctx, w.psURL+w.ps.paths.Revocation, aauth.RevocationRequest{JTI: jti, Exp: time.Now().Add(time.Hour).Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times", n)
	}
}
