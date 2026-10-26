package agentprovider

import (
	"context"
	"net/http"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// An issuance request signed for another host is refused.
func TestRequestForAnotherAuthorityRefused(t *testing.T) {
	ta := newAP(t, nil)
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ta.client.newRequest(context.Background(), ta.url+DefaultPaths().Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "other.example"
	req.Header.Set("X-Session", "alice")
	if err := SignHWK(req, key); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
}
