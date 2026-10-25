package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"

	aauth "github.com/aauth-dev/aauth-go"
)

// billingGate stands in front of the four-party access server as an AS
// that requires a billing relationship with a PS before it issues auth
// tokens (draft -11 §9.1.2). The PS's first token request is answered 402
// with a Location and a Payment challenge; once the PS's payment handler
// has settled, its poll of that Location delivers the held request to the
// access server, which continues as usual.
type billingGate struct {
	tokenPath string

	mu       sync.Mutex
	billed   bool
	held     *http.Request
	heldBody []byte
	settled  []*aauth.PaymentRequiredError
}

const billingPending = "/billing/pending/1"

// Settle implements aauth.PaymentHandler for the PS.
func (g *billingGate) Settle(_ context.Context, p *aauth.PaymentRequiredError) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.settled = append(g.settled, p)
	g.billed = true
	return nil
}

// settlements returns the payments the PS settled.
func (g *billingGate) settlements() []*aauth.PaymentRequiredError {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.settled
}

// serve handles billing for r, reporting whether it answered.
func (g *billingGate) serve(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == g.tokenPath && !g.billed && g.held == nil:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		g.held, g.heldBody = r.Clone(context.Background()), body
		g.paymentRequired(w)
		return true
	case r.Method == http.MethodGet && r.URL.Path == billingPending:
		if !g.billed || g.held == nil {
			g.paymentRequired(w)
			return true
		}
		// Billing is established: deliver the held, PS-signed token
		// request to the access server.
		held := g.held.Clone(r.Context())
		held.Body = io.NopCloser(bytes.NewReader(g.heldBody))
		g.held = nil
		g.mu.Unlock()
		next.ServeHTTP(w, held)
		g.mu.Lock()
		return true
	}
	return false
}

func (g *billingGate) paymentRequired(w http.ResponseWriter) {
	w.Header().Set(aauth.HeaderLocation, billingPending)
	w.Header().Set("WWW-Authenticate", `Payment id="bill-ps", method="example", request="eyJhbW91bnQiOiIwIn0"`)
	w.WriteHeader(http.StatusPaymentRequired)
}
