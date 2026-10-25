package aauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authorizeWorld is the three-party world with a resource that publishes an
// authorization endpoint (§6.6) served by an [AuthorizationHandler].
type authorizeWorld struct {
	*threePartyWorld
	decide func(ctx context.Context, r *http.Request, person *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error)
	noEP   bool // publish no authorization_endpoint
	// refuse, when set, may answer an authorization request before the
	// handler does, returning true when it did.
	refuse func(rw http.ResponseWriter) bool
}

func newAuthorizeWorld(t *testing.T) *authorizeWorld {
	t.Helper()
	w := &authorizeWorld{threePartyWorld: newThreePartyWorld(t)}
	mux := http.NewServeMux()
	var url string
	mux.HandleFunc("GET /.well-known/"+WellKnownResource, func(rw http.ResponseWriter, _ *http.Request) {
		md := ResourceMetadata{ServerMetadata: ServerMetadata{Issuer: url, JWKSURI: url + "/jwks"}}
		if !w.noEP {
			md.AuthorizationEndpoint = url + "/authorize"
		}
		writeJSON(t, rw, md)
	})
	ah := &AuthorizationHandler{
		Verify: TokenVerifyOptions{InsecureSkipIdentifierCheck: true},
		Decide: func(ctx context.Context, r *http.Request, p *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error) {
			return w.decide(ctx, r, p, req)
		},
	}
	mux.Handle("/authorize", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.refuse != nil && w.refuse(rw) {
			return
		}
		ah.ServeHTTP(rw, r)
	}))
	mux.HandleFunc("GET /pending/authz", func(rw http.ResponseWriter, _ *http.Request) {
		WriteAuthorized(rw, "files:read", "sess-after-interaction")
	})
	mux.HandleFunc("GET /files", w.serveResource(t, func() string { return url }, "files:read", nil))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	url = srv.URL
	// The world's PS and transport resolve the resource by w.resourceURL.
	w.resourceURL = url
	ah.Resource = url
	ah.Verify.Resolver = StaticResolver{w.psURL: w.psAgent.JWKS()}
	return w
}

func (w *authorizeWorld) issueRT(req AuthorizeRequest, p *PersonClaims) (AuthorizeDecision, error) {
	rt, err := IssueResourceToken(ResourceTokenParams{Resource: w.resourceURL, Scope: req.Scope, Account: req.Account}, p, w.resourceKey.Key, w.resourceKey.JWK().Kid)
	return AuthorizeDecision{ResourceToken: rt}, err
}

func TestAuthorizeResourceToken(t *testing.T) {
	// §6.6.2: the resource returns a resource token; the agent redeems it
	// at the PS and later calls present the cached auth token.
	w := newAuthorizeWorld(t)
	w.decide = func(_ context.Context, _ *http.Request, p *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error) {
		if req.Scope != "files:read" || req.Account != "acct-7" {
			t.Errorf("request %+v", req)
		}
		return w.issueRT(req, p)
	}
	tr := w.transport()
	res, err := tr.Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "files:read", Account: "acct-7"})
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthToken == "" || res.Status != "" {
		t.Fatalf("result %+v", res)
	}
	resp, err := (&http.Client{Transport: tr}).Get(w.resourceURL + "/files")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	closeBody(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(b) != "hello person-1 scope=files:read" {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	if p, a := w.personRequests.Load(), w.authRequests.Load(); p != 1 || a != 1 {
		t.Fatalf("person token requests %d, auth token requests %d; want 1 and 1", p, a)
	}
}

func TestAuthorizeOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		caps     []string
		decision AuthorizeDecision
		err      error
		want     AuthorizeResult
		wantCode string
	}{
		{name: "authorized with session", decision: AuthorizeDecision{Scope: "files:read", SessionToken: "sess-1"},
			want: AuthorizeResult{Status: AuthorizeStatusAuthorized, Scope: "files:read", SessionToken: "sess-1"}},
		{name: "authorized without session", decision: AuthorizeDecision{Scope: "files:read"},
			want: AuthorizeResult{Status: AuthorizeStatusAuthorized, Scope: "files:read"}},
		{name: "invalid scope", err: &ProblemError{Status: http.StatusBadRequest, Code: ErrCodeInvalidScope}, wantCode: ErrCodeInvalidScope},
		{name: "invalid account", err: &ProblemError{Status: http.StatusBadRequest, Code: ErrCodeInvalidAccount}, wantCode: ErrCodeInvalidAccount},
		{name: "other error is server_error", err: errors.New("database down"), wantCode: ErrCodeServerError},
		{name: "interaction declared", caps: []string{CapabilityInteraction},
			decision: AuthorizeDecision{Pending: &PendingInteraction{Location: "/pending/authz", InteractionURL: "https://files.example/consent", Code: "ABCD-EFGH"}},
			want:     AuthorizeResult{Status: AuthorizeStatusAuthorized, Scope: "files:read", SessionToken: "sess-after-interaction"}},
		{name: "interaction not declared", decision: AuthorizeDecision{Pending: &PendingInteraction{Location: "/pending/authz"}},
			wantCode: TokenErrUserUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newAuthorizeWorld(t)
			w.decide = func(context.Context, *http.Request, *PersonClaims, AuthorizeRequest) (AuthorizeDecision, error) {
				return tc.decision, tc.err
			}
			tr := w.transport()
			tr.Capabilities = tc.caps
			var interactions []Requirement
			tr.OnRequirement = func(r Requirement) { interactions = append(interactions, r) }
			got, err := tr.Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "files:read"})
			if tc.wantCode != "" {
				var pe *ProblemError
				if !errors.As(err, &pe) || pe.Code != tc.wantCode {
					t.Fatalf("err = %v, want problem %s", err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if *got != tc.want {
				t.Fatalf("got %+v, want %+v", *got, tc.want)
			}
			if tc.decision.Pending != nil && (len(interactions) != 1 || interactions[0].Code != "ABCD-EFGH") {
				t.Fatalf("interaction surfaced %+v", interactions)
			}
		})
	}
}

func TestAuthorizeNoEndpoint(t *testing.T) {
	w := newAuthorizeWorld(t)
	w.noEP = true
	_, err := w.transport().Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "files:read"})
	if !errors.Is(err, ErrNoAuthorizationEndpoint) {
		t.Fatalf("err = %v", err)
	}
	if _, err := w.transport().Authorize(context.Background(), w.resourceURL, AuthorizeRequest{}); err == nil {
		t.Fatal("empty scope: want error")
	}
	if _, err := NewTransport(w.agent, nil).Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "x"}); err == nil {
		t.Fatal("no PS: want error")
	}
}

func TestAuthorizationHandlerRejects(t *testing.T) {
	w := newAuthorizeWorld(t)
	w.decide = func(context.Context, *http.Request, *PersonClaims, AuthorizeRequest) (AuthorizeDecision, error) {
		t.Error("Decide called for a rejected request")
		return AuthorizeDecision{}, nil
	}
	ctx := context.Background()
	person, err := w.transport().personToken(ctx, w.resourceURL)
	if err != nil {
		t.Fatal(err)
	}
	agentTok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		method     string
		token      string // "" sends no Signature-Key
		body       string
		wantStatus int
		wantReq    string // AAuth-Requirement requirement value
		wantCode   string
	}{
		{"GET", http.MethodGet, person, "", http.StatusMethodNotAllowed, "", ErrCodeInvalidRequest},
		{"no signature key", http.MethodPost, "", `{"scope":"a"}`, http.StatusUnauthorized, RequirementPersonToken, ""},
		{"agent token", http.MethodPost, agentTok, `{"scope":"a"}`, http.StatusUnauthorized, RequirementPersonToken, ""},
		{"missing scope", http.MethodPost, person, `{"account":"x"}`, http.StatusBadRequest, "", ErrCodeInvalidRequest},
		{"not JSON", http.MethodPost, person, `scope=a`, http.StatusBadRequest, "", ErrCodeInvalidRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req, err := http.NewRequestWithContext(ctx, tc.method, w.resourceURL+"/authorize", body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.token != "" {
				AttachSignatureKey(req, tc.token)
				if err := SignRequest(req, w.agent.Key, ""); err != nil {
					t.Fatal(err)
				}
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(res.Body)
			closeBody(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status %d: %s", res.StatusCode, b)
			}
			if tc.wantReq != "" {
				r, err := ParseRequirement(res.Header.Get(HeaderRequirement))
				if err != nil || r.Requirement != tc.wantReq {
					t.Fatalf("requirement %q (%v)", res.Header.Get(HeaderRequirement), err)
				}
			}
			if tc.wantCode != "" {
				var pe *ProblemError
				if !errors.As(endpointError("authorize", res, b), &pe) || pe.Code != tc.wantCode {
					t.Fatalf("body %s, want code %s", b, tc.wantCode)
				}
			}
		})
	}
}

func TestAuthorizeReplacesARefusedPersonToken(t *testing.T) {
	refusals := map[string]func(rw http.ResponseWriter){
		"person-token requirement": ChallengePersonToken,
		"expired person token": func(rw http.ResponseWriter) {
			WriteSignatureError(rw, SignatureError{Code: SigErrExpiredJWT}, "expired")
		},
		"revoked person token": func(rw http.ResponseWriter) {
			WriteSignatureError(rw, SignatureError{Code: SigErrRevokedJWT}, "revoked")
		},
	}
	for name, refuse := range refusals {
		t.Run(name, func(t *testing.T) {
			w := newAuthorizeWorld(t)
			w.decide = func(_ context.Context, _ *http.Request, p *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error) {
				return w.issueRT(req, p)
			}
			first := true
			w.refuse = func(rw http.ResponseWriter) bool {
				if !first {
					return false
				}
				first = false
				refuse(rw)
				return true
			}
			res, err := w.transport().Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "files:read"})
			if err != nil {
				t.Fatal(err)
			}
			if res.AuthToken == "" {
				t.Fatalf("result %+v", res)
			}
			if p := w.personRequests.Load(); p != 2 {
				t.Fatalf("person token requests %d, want 2: the refused token is replaced once", p)
			}
		})
	}
}

func TestAuthorizeDoesNotRetryOtherRefusals(t *testing.T) {
	w := newAuthorizeWorld(t)
	w.decide = func(_ context.Context, _ *http.Request, p *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error) {
		return w.issueRT(req, p)
	}
	refusals := 0
	w.refuse = func(rw http.ResponseWriter) bool {
		refusals++
		WriteSignatureError(rw, SignatureError{Code: SigErrInvalidSignature}, "bad signature")
		return true
	}
	if _, err := w.transport().Authorize(context.Background(), w.resourceURL, AuthorizeRequest{Scope: "files:read"}); err == nil {
		t.Fatal("an invalid_signature refusal succeeded")
	}
	if refusals != 1 || w.personRequests.Load() != 1 {
		t.Fatalf("refusals %d, person token requests %d; want one of each", refusals, w.personRequests.Load())
	}

	// A refused replacement is not replaced again.
	w2 := newAuthorizeWorld(t)
	w2.refuse = func(rw http.ResponseWriter) bool {
		ChallengePersonToken(rw)
		return true
	}
	if _, err := w2.transport().Authorize(context.Background(), w2.resourceURL, AuthorizeRequest{Scope: "files:read"}); err == nil {
		t.Fatal("a resource refusing every person token was authorized")
	}
	if p := w2.personRequests.Load(); p != 2 {
		t.Fatalf("person token requests %d, want 2", p)
	}
}
