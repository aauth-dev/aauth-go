package aauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// revocationRecipient is a recipient's revocation endpoint (§11.12) that
// verifies the jwks_uri-signed caller and records (iss, jti).
type revocationRecipient struct {
	srv      *httptest.Server
	recorded map[string]int64 // iss + " " + jti → exp
	reply    func(http.ResponseWriter, *ServerCaller) bool
	polls    atomic.Int32
	pollers  []string
}

func newRevocationRecipient(t *testing.T) *revocationRecipient {
	t.Helper()
	rr := &revocationRecipient{recorded: map[string]int64{}}
	verify := func(r *http.Request) (*ServerCaller, error) {
		return VerifyServerRequest(r.Context(), r, VerifyServerOptions{
			InsecureSkipIdentifierCheck: true,
			Resolver:                    NewJWKSResolver(nil),
			Signature:                   RequestVerifyOptions{RequireBodyCoverage: true},
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /revoke", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := verify(r)
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		req, err := ParseRevocationRequest(r)
		if err != nil {
			var pe *ProblemError
			errors.As(err, &pe)
			WriteProblem(rw, pe.Status, pe.Code, pe.Detail)
			return
		}
		rr.recorded[caller.ID+" "+req.JTI] = req.Exp
		if rr.reply == nil || !rr.reply(rw, caller) {
			rw.WriteHeader(http.StatusOK) // empty body: nothing downstream
		}
	})
	mux.HandleFunc("GET /pending/r1", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := verify(r)
		if err != nil {
			http.NotFound(rw, r) // §11.12.3: 404 to any other identity
			return
		}
		rr.pollers = append(rr.pollers, caller.ID)
		if rr.polls.Add(1) < 2 {
			rw.Header().Set(HeaderLocation, "/pending/r1")
			rw.Header().Set(HeaderRetryAfter, "0")
			rw.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(t, rw, RevocationResponse{Downstream: []RevocationOutcome{
			{Recipient: "https://resource.example"},
			{Recipient: "https://slow.example", Error: RevocationUnavailable},
		}})
	})
	rr.srv = httptest.NewServer(mux)
	t.Cleanup(rr.srv.Close)
	return rr
}

func TestRevoke(t *testing.T) {
	jwks, signer := psSigner(t)
	rr := newRevocationRecipient(t)
	c := &RevocationClient{Signer: signer}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := time.Now().Add(time.Hour).Unix()

	// A recipient with nothing downstream answers at once, empty.
	res, err := c.Revoke(ctx, rr.srv.URL+"/revoke", RevocationRequest{JTI: "pt-1", Exp: exp})
	if err != nil || len(res.Downstream) != 0 {
		t.Fatalf("res %+v, err %v", res, err)
	}
	// Keyed by the verified caller, not a parameter (§11.12.1).
	if rr.recorded[jwks.srv.URL+" pt-1"] != exp {
		t.Fatalf("recorded %v", rr.recorded)
	}

	// An AS cascading: 202, polled under the same identity, then the
	// downstream report.
	rr.reply = func(rw http.ResponseWriter, _ *ServerCaller) bool {
		rw.Header().Set(HeaderLocation, "/pending/r1")
		rw.Header().Set(HeaderRetryAfter, "0")
		rw.WriteHeader(http.StatusAccepted)
		return true
	}
	res, err = c.Revoke(ctx, rr.srv.URL+"/revoke", RevocationRequest{JTI: "pt-2", Exp: exp})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Downstream) != 2 || res.Downstream[1].Error != RevocationUnavailable || len(rr.pollers) != 2 || rr.pollers[0] != jwks.srv.URL {
		t.Fatalf("res %+v, pollers %v", res, rr.pollers)
	}
}

func TestRevokeErrors(t *testing.T) {
	_, signer := psSigner(t)
	rr := newRevocationRecipient(t)
	c := &RevocationClient{Signer: signer}
	ctx := context.Background()
	req := RevocationRequest{JTI: "at-1", Exp: time.Now().Add(time.Hour).Unix()}
	endpoint := rr.srv.URL + "/revoke"

	for name, tc := range map[string]struct {
		reply   func(http.ResponseWriter)
		check   func(error) bool
		outcome string
	}{
		"unsupported_iss": {
			func(rw http.ResponseWriter) { WriteProblem(rw, http.StatusForbidden, ErrCodeUnsupportedIss, "") },
			func(err error) bool { return errors.Is(err, ErrRevocationUnsupported) },
			RevocationUnsupported,
		},
		"rate_limited": {
			func(rw http.ResponseWriter) {
				rw.Header().Set(HeaderRetryAfter, "30")
				WriteProblem(rw, http.StatusTooManyRequests, ErrCodeRateLimited, "")
			},
			func(err error) bool {
				var pe *ProblemError
				return errors.As(err, &pe) && pe.Code == ErrCodeRateLimited && pe.RetryAfter == 30*time.Second
			},
			RevocationUnavailable,
		},
		"5xx without a problem body": {
			func(rw http.ResponseWriter) { http.Error(rw, "boom", http.StatusBadGateway) },
			func(err error) bool { return errors.Is(err, ErrRevocationUnavailable) },
			RevocationUnavailable,
		},
		"malformed 200 body": {
			func(rw http.ResponseWriter) { writeBody(t, rw, "not json") },
			func(err error) bool { return errors.Is(err, ErrRevocationUnavailable) },
			RevocationUnavailable,
		},
	} {
		rr.reply = func(rw http.ResponseWriter, _ *ServerCaller) bool { tc.reply(rw); return true }
		_, err := c.Revoke(ctx, endpoint, req)
		if !tc.check(err) {
			t.Errorf("%s: err = %v", name, err)
		}
		if got := RevocationOutcomeFor("https://r.example", err); got.Error != tc.outcome {
			t.Errorf("%s: outcome %+v", name, got)
		}
	}
	if got := RevocationOutcomeFor("https://r.example", nil); got.Error != "" || got.Recipient != "https://r.example" {
		t.Errorf("success outcome %+v", got)
	}
	// No endpoint at all.
	if _, err := c.Revoke(ctx, "", req); RevocationOutcomeFor("x", err).Error != RevocationUnsupported {
		t.Errorf("no endpoint: err = %v", err)
	}
	// The recipient answers malformed requests with invalid_request.
	rr.reply = nil
	for _, bad := range []string{`{"jti":"x"}`, `{"exp":1}`, `{"jti":"x","exp":1.5}`, `nope`} {
		r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(bad))
		var pe *ProblemError
		if _, err := ParseRevocationRequest(r); !errors.As(err, &pe) || pe.Code != ErrCodeInvalidRequest {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
	if _, err := c.Revoke(ctx, endpoint, RevocationRequest{JTI: "x"}); err == nil {
		t.Error("revocation without exp sent")
	}
}

func TestRevocationEndpointDiscovery(t *testing.T) {
	var base string
	withEndpoint := true
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		md := ResourceMetadata{ServerMetadata: ServerMetadata{Issuer: base}}
		if withEndpoint {
			md.RevocationEndpoint = base + "/revoke"
		}
		writeJSON(t, rw, md)
	}))
	defer srv.Close()
	base = srv.URL
	ep, err := RevocationEndpoint(context.Background(), nil, base, WellKnownResource)
	if err != nil || ep != base+"/revoke" {
		t.Fatalf("endpoint %q, %v", ep, err)
	}
	withEndpoint = false
	if _, err := RevocationEndpoint(context.Background(), nil, base, WellKnownResource); !errors.Is(err, ErrRevocationUnsupported) {
		t.Fatalf("no endpoint: err = %v", err)
	}
}
