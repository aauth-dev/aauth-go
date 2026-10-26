package personserver

import (
	"context"
	"net/http"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// A terminal response is returned once; afterwards the pending URL is
// gone (§11.8.3) and the stored body is discarded.
func TestTerminalResponseDeliveredOnce(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	loc, id := deferAuthToken(t, w, pt, "files:read")
	if err := w.ps.Approve(ctx, id, Grant{}); err != nil {
		t.Fatal(err)
	}
	pollToken(t, w, loc)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		res := w.signed(w.agent, "", method, loc, nil)
		if code := errorCode(t, res); res.StatusCode != http.StatusGone || code != aauth.ErrCodeInvalidRequest {
			t.Errorf("%s after delivery: %d %s", method, res.StatusCode, code)
		}
	}
	p, err := w.ps.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Delivered || p.Result == nil || len(p.Result.Body) != 0 || p.Result.Status != http.StatusOK {
		t.Fatalf("pending after delivery %+v", p)
	}
}
