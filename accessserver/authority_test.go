package accessserver

import (
	"net/http"
	"strings"
	"testing"
)

// A PS request signed for another host is refused at the AS.
func TestRequestForAnotherAuthorityRefused(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	req, err := http.NewRequest(http.MethodPost, f.asURL+"/as/token", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "other.example"
	if err := f.ps.Signer().SignRequest(req); err != nil {
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
