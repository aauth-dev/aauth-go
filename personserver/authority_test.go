package personserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// A request signed for another host is refused: a server the agent called
// cannot replay that request to the PS within the signature window.
func TestRequestForAnotherAuthorityRefused(t *testing.T) {
	w := newWorld(t, nil)
	body, err := json.Marshal(aauth.PersonTokenRequest{Resource: w.resURL})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, w.psURL+w.ps.paths.PersonToken, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "other.example" // what the agent signed for
	tok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	aauth.AttachSignatureKey(req, tok)
	if err := aauth.SignRequest(req, w.agent.Key, ""); err != nil {
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
