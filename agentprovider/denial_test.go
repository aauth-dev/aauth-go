package agentprovider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// A refusal by the Registrar or the attestation verifier is answered with
// a generic denial; their error text stays in the provider's log.
func TestDenialsDoNotEchoErrors(t *testing.T) {
	ctx := context.Background()
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ta := newAP(t, nil)
	_, err = ta.client.Issue(ctx, key, nil) // no session: the Registrar refuses
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "no session") {
		t.Fatalf("registrar refusal: %v", err)
	}
	bad := newAP(t, attester{fail: true})
	bad.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	_, err = bad.client.Issue(ctx, key, map[string]any{"attestation": map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "untrusted device") {
		t.Fatalf("attestation refusal: %v", err)
	}
}
