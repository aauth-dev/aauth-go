package aauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestNewPaymentRequiredError(t *testing.T) {
	base, err := url.Parse("https://as.example/token")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		h          map[string][]string
		wantErr    bool
		wantLoc    string
		wantReq    string
		wantPayChs int
	}{
		{name: "location resolved", h: map[string][]string{"Location": {"/pending/xyz"}}, wantLoc: "https://as.example/pending/xyz"},
		{name: "no location", h: nil},
		{name: "cross-origin location", h: map[string][]string{"Location": {"https://evil.example/p"}}, wantErr: true},
		{name: "with auth-token requirement", h: map[string][]string{HeaderRequirement: {`requirement=auth-token; resource-token="eyJ"`}}, wantReq: RequirementAuthToken},
		{name: "malformed requirement", h: map[string][]string{HeaderRequirement: {"requirement"}}, wantErr: true},
		{name: "payment challenges filtered", h: map[string][]string{"Www-Authenticate": {`Payment id="x7", method="example"`, `Bearer realm="api"`, `payment id="y"`}}, wantPayChs: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, vs := range tc.h {
				for _, v := range vs {
					h.Add(k, v)
				}
			}
			pr, err := NewPaymentRequiredError(base, h, []byte(`{"x402Version":1}`))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err != nil {
				return
			}
			if pr.Server != "https://as.example" || pr.Location != tc.wantLoc || string(pr.Body) != `{"x402Version":1}` {
				t.Fatalf("%+v", pr)
			}
			if (pr.Requirement == nil && tc.wantReq != "") || (pr.Requirement != nil && pr.Requirement.Requirement != tc.wantReq) {
				t.Fatalf("requirement %+v", pr.Requirement)
			}
			if got := len(pr.PaymentChallenges()); got != tc.wantPayChs {
				t.Fatalf("payment challenges %d, want %d", got, tc.wantPayChs)
			}
			if pr.Error() == "" {
				t.Fatal("empty error string")
			}
		})
	}
}

// payServer answers POST /buy with 402 naming /pending/pay until paid, and
// the pending URL with 200 once paid.
func payServer(t *testing.T, paid *atomic.Bool, alwaysUnpaid bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /buy", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set(HeaderLocation, "/pending/pay")
		rw.Header().Set("WWW-Authenticate", `Payment id="x7Tg2pLq", method="example"`)
		rw.WriteHeader(http.StatusPaymentRequired)
	})
	mux.HandleFunc("GET /pending/pay", func(rw http.ResponseWriter, _ *http.Request) {
		if alwaysUnpaid || !paid.Load() {
			rw.Header().Set(HeaderLocation, "/pending/pay")
			rw.Header().Set("WWW-Authenticate", `Payment id="x7Tg2pLq", method="example"`)
			rw.WriteHeader(http.StatusPaymentRequired)
			return
		}
		writeBody(t, rw, "receipt")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFollowDeferredSettlesPayment(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name         string
		handler      bool
		alwaysUnpaid bool
		wantStatus   int
		wantErr      bool
		wantSettles  int32
	}{
		{name: "settled then polled", handler: true, wantStatus: http.StatusOK, wantSettles: 1},
		{name: "no handler returns the 402", wantStatus: http.StatusPaymentRequired},
		{name: "settlements bounded", handler: true, alwaysUnpaid: true, wantErr: true, wantSettles: maxSettlements},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var paid atomic.Bool
			var settles atomic.Int32
			srv := payServer(t, &paid, tc.alwaysUnpaid)
			opts := DeferredOptions{}
			if tc.handler {
				opts.Payment = PaymentHandlerFunc(func(_ context.Context, p *PaymentRequiredError) error {
					settles.Add(1)
					if len(p.PaymentChallenges()) != 1 {
						t.Errorf("challenges %q", p.Challenges)
					}
					paid.Store(true)
					return nil
				})
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/buy", nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := DoDeferred(ctx, srv.Client(), req, opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err == nil {
				closeBody(res.Body)
				if res.StatusCode != tc.wantStatus {
					t.Fatalf("status %d, want %d", res.StatusCode, tc.wantStatus)
				}
			}
			if got := settles.Load(); got != tc.wantSettles {
				t.Fatalf("settled %d times, want %d", got, tc.wantSettles)
			}
		})
	}
}

func TestTransportSettlesResourcePayment(t *testing.T) {
	// A resource that answers 402 without Location until the agent pays,
	// then serves the retried request (§6.5).
	agent := testAgent(t)
	var paid atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		if !paid.Load() {
			if !CanRequirePayment(req) {
				t.Error("402 to an agent that did not declare payment")
			}
			rw.Header().Set("WWW-Authenticate", `Payment id="r1", method="example"`)
			rw.WriteHeader(http.StatusPaymentRequired)
			return
		}
		writeBody(t, rw, "paid content")
	}))
	defer srv.Close()

	tr := NewTransport(agent, nil)
	tr.Capabilities = []string{CapabilityPayment}
	tr.Payment = PaymentHandlerFunc(func(_ context.Context, p *PaymentRequiredError) error {
		if p.Location != "" || p.Server != srv.URL {
			t.Errorf("payment %+v", p)
		}
		paid.Store(true)
		return nil
	})
	res, err := (&http.Client{Transport: tr}).Get(srv.URL + "/article")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	closeBody(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || string(b) != "paid content" {
		t.Fatalf("status %d: %s", res.StatusCode, b)
	}

	// A refused settlement stops the request.
	paid.Store(false)
	tr.Payment = PaymentHandlerFunc(func(context.Context, *PaymentRequiredError) error { return errors.New("card declined") })
	if _, err := (&http.Client{Transport: tr}).Get(srv.URL + "/article"); err == nil {
		t.Fatal("refused settlement: want error")
	}
	// Without a handler the 402 reaches the caller.
	tr.Payment = nil
	res, err = (&http.Client{Transport: tr}).Get(srv.URL + "/article")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := PaymentRequiredFromResponse(res.Request.URL, res)
	if err != nil || res.StatusCode != http.StatusPaymentRequired || len(pr.PaymentChallenges()) != 1 {
		t.Fatalf("status %d %+v %v", res.StatusCode, pr, err)
	}
}

func TestTransportPaymentWithAuthToken(t *testing.T) {
	// §6.5, §11.6: a 402 with requirement=auth-token says authorization and
	// payment are both required. The agent obtains the auth token, pays,
	// and retries with the auth token.
	w := newThreePartyWorld(t)
	var paid atomic.Bool
	mux := http.NewServeMux()
	var url string
	mux.HandleFunc("GET /report", func(rw http.ResponseWriter, r *http.Request) {
		tok, err := ParseSignatureKey(r)
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		typ, err := TokenType(tok)
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		switch typ {
		case TypAuth:
			if _, err := VerifyAndExtractAuth(r.Context(), r, url, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(w.resolver())}); err != nil {
				WriteSignatureFailure(rw, err)
				return
			}
			if !paid.Load() {
				t.Error("auth token presented before payment settled")
			}
			writeBody(t, rw, "report")
		case TypPerson:
			person, err := VerifyAndExtractPerson(r.Context(), r, url, localOpts(w.resolver()))
			if err != nil {
				WriteSignatureFailure(rw, err)
				return
			}
			rt, err := IssueResourceToken(ResourceTokenParams{Resource: url, Scope: "reports:read"}, person, w.resourceKey.Key, w.resourceKey.JWK().Kid)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			rw.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAuthToken, ResourceToken: rt}.String())
			rw.WriteHeader(http.StatusPaymentRequired)
		default:
			ChallengePersonToken(rw)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url = srv.URL
	w.resourceURL = url

	tr := w.transport()
	tr.Capabilities = []string{CapabilityPayment}
	tr.Payment = PaymentHandlerFunc(func(context.Context, *PaymentRequiredError) error {
		paid.Store(true)
		return nil
	})
	res, err := (&http.Client{Transport: tr}).Get(url + "/report")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	closeBody(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || string(b) != "report" {
		t.Fatalf("status %d: %s", res.StatusCode, b)
	}
	if a := w.authRequests.Load(); a != 1 {
		t.Fatalf("auth token requests %d, want 1", a)
	}
}
