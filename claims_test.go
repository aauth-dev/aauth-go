package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fixedClock returns verifier options whose clock reads now.
func fixedClock(now time.Time) RequestVerifyOptions {
	return RequestVerifyOptions{Now: func() time.Time { return now }}
}

// mintTestAuth mints an auth token from iss for aud, bound to a's key,
// letting mutate adjust the claims first.
func mintTestAuth(t *testing.T, issuer *Agent, a *Agent, iss, aud string, now time.Time, mutate func(*AuthClaims)) string {
	t.Helper()
	jwk := a.JWK()
	c := AuthClaims{
		DWK:   WellKnownPerson,
		PS:    iss,
		Scope: "files:read",
		Cnf:   Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{aud},
			ID:        "auth-1",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	if mutate != nil {
		mutate(&c)
	}
	tok, err := MintAuthToken(c, issuer.Key, issuer.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCommonClaimRules(t *testing.T) {
	ps := testAgent(t)
	agent := testAgent(t)
	const iss, aud = "https://ps.example", "https://resource.example"
	now := time.Unix(1767225600, 0)
	opts := TokenVerifyOptions{Resolver: StaticResolver{iss: ps.JWKS()}, Signature: fixedClock(now)}
	ctx := context.Background()

	cases := []struct {
		name   string
		mutate func(*AuthClaims)
		opts   func(TokenVerifyOptions) TokenVerifyOptions
		want   error // nil means accepted
	}{
		{name: "valid", want: nil},
		{name: "iat missing", mutate: func(c *AuthClaims) { c.IssuedAt = nil }, want: ErrMissingClaim},
		{name: "exp missing", mutate: func(c *AuthClaims) { c.ExpiresAt = nil }, want: ErrMissingClaim},
		{name: "iat within window ahead", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(30 * time.Second))
		}, want: nil},
		{name: "iat beyond window ahead", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(2 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
		}, want: ErrClockSkew},
		{name: "iat ahead within a widened window", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(2 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
		}, opts: func(o TokenVerifyOptions) TokenVerifyOptions {
			o.Signature.Window = 5 * time.Minute
			return o
		}, want: nil},
		{name: "exp equal to now", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now)
		}, want: ErrExpired},
		{name: "exp one second ago (no leeway)", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second))
		}, want: ErrExpired},
		{name: "lifetime over one hour", mutate: func(c *AuthClaims) {
			c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour + time.Second))
		}, want: ErrInvalidToken},
		{name: "iss not a server identifier", mutate: func(c *AuthClaims) { c.Issuer = "https://ps.example:8443"; c.PS = c.Issuer }, opts: func(o TokenVerifyOptions) TokenVerifyOptions {
			o.Resolver = StaticResolver{"https://ps.example:8443": ps.JWKS()}
			return o
		}, want: ErrInvalidToken},
		{name: "iss check skipped for local development", mutate: func(c *AuthClaims) { c.Issuer = "http://127.0.0.1:8080"; c.PS = c.Issuer }, opts: func(o TokenVerifyOptions) TokenVerifyOptions {
			o.Resolver = StaticResolver{"http://127.0.0.1:8080": ps.JWKS()}
			o.InsecureSkipIdentifierCheck = true
			return o
		}, want: nil},
		{name: "unexpected dwk", mutate: func(c *AuthClaims) { c.DWK = WellKnownAgent }, want: ErrInvalidToken},
		{name: "expired with wrong aud is invalid, not expired", mutate: func(c *AuthClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second))
			c.Audience = jwt.ClaimStrings{"https://other.example"}
		}, want: ErrInvalidToken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := opts
			if c.opts != nil {
				o = c.opts(o)
			}
			tok := mintTestAuth(t, ps, agent, iss, aud, now, c.mutate)
			_, err := VerifyAuthToken(ctx, tok, aud, AuthTokenVerifyOptions{TokenVerifyOptions: o})
			switch {
			case c.want == nil && err != nil:
				t.Fatalf("rejected: %v", err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.want == ErrInvalidToken && errors.Is(err, ErrExpired) {
				t.Fatalf("err = %v also matches ErrExpired", err)
			}
		})
	}
}

func TestVerifyAuthTokenSelfSignedCnf(t *testing.T) {
	// The resolver receives the token's cnf.jwk (it was once passed nil).
	a := testAgent(t)
	now := time.Now()
	tok := mintTestAuth(t, a, a, "https://ps.example", "https://resource.example", now, nil)
	if _, err := VerifyAuthToken(context.Background(), tok, "https://resource.example", AuthTokenVerifyOptions{TokenVerifyOptions: TokenVerifyOptions{Resolver: SelfSignedResolver{}}}); err != nil {
		t.Fatalf("self-signed auth token: %v", err)
	}
}

func TestAgentTokenRequiresIat(t *testing.T) {
	a := testAgent(t)
	jwk := a.JWK()
	claims := AgentClaims{DWK: WellKnownAgent, Cnf: Cnf{JWK: &jwk}}
	claims.Subject = a.ID.String()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tok, err := MintAgentToken(claims, a.Key, jwk.Kid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("err = %v, want ErrMissingClaim", err)
	}
	// A skewed clock: the agent's iat is ahead of the verifier's.
	tok, err = a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}, Signature: fixedClock(time.Now().Add(-5 * time.Minute))}
	_, err = VerifyAgentToken(context.Background(), tok, opts)
	if !errors.Is(err, ErrClockSkew) {
		t.Fatalf("err = %v, want ErrClockSkew", err)
	}
	if e, ok := SignatureErrorFor(err); !ok || e.Code != SigErrClockSkew {
		t.Fatalf("Signature-Error = %+v, want clock_skew", e)
	}
}

func TestBoundedExpiry(t *testing.T) {
	now := time.Unix(1767225600, 0)
	cases := []struct {
		name   string
		ttl    time.Duration
		bounds []time.Time
		want   time.Time
		err    error
	}{
		{name: "default to max", want: now.Add(time.Hour)},
		{name: "ttl over max capped", ttl: 2 * time.Hour, want: now.Add(time.Hour)},
		{name: "shorter ttl", ttl: 10 * time.Minute, want: now.Add(10 * time.Minute)},
		{name: "agent token bound", bounds: []time.Time{now.Add(20 * time.Minute)}, want: now.Add(20 * time.Minute)},
		{name: "earliest of several bounds", bounds: []time.Time{now.Add(50 * time.Minute), {}, now.Add(15 * time.Minute)}, want: now.Add(15 * time.Minute)},
		{name: "sub-second bound truncated down", bounds: []time.Time{now.Add(90*time.Second + 500*time.Millisecond)}, want: now.Add(90 * time.Second)},
		{name: "bound already passed", bounds: []time.Time{now.Add(-time.Second)}, err: ErrExpired},
		{name: "bound equal to now", bounds: []time.Time{now}, err: ErrExpired},
	}
	for _, c := range cases {
		got, err := BoundedExpiry(now, c.ttl, MaxPersonTokenLifetime, c.bounds...)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: err = %v, want %v", c.name, err, c.err)
			}
			continue
		}
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
}

func TestNewTokenParamError(t *testing.T) {
	cases := []struct {
		param string
		err   error
		code  string
	}{
		{ParamPresentedToken, ErrExpired, TokenErrExpiredPresentedToken},
		{ParamPresentedToken, ErrRevoked, TokenErrRevokedPresentedToken},
		{ParamPresentedToken, ErrWrongTokenType, TokenErrInvalidPresentedToken},
		{ParamUpstreamToken, ErrInvalidToken, TokenErrInvalidUpstreamToken},
		{ParamUpstreamToken, ErrExpired, TokenErrExpiredUpstreamToken},
		{ParamUpstreamToken, ErrRevoked, TokenErrRevokedUpstreamToken},
		{ParamSubagentToken, ErrUnknownKey, TokenErrInvalidSubagentToken},
		{ParamSubagentToken, ErrExpired, TokenErrExpiredSubagentToken},
		{ParamSubagentToken, ErrRevoked, TokenErrRevokedSubagentToken},
		{ParamResourceToken, ErrMissingClaim, TokenErrInvalidResourceToken},
		{ParamResourceToken, ErrClockSkew, TokenErrClockSkew},
		{ParamResourceToken, errors.New("dial tcp: refused"), TokenErrServerError},
	}
	for _, c := range cases {
		te := NewTokenParamError(c.param, c.err)
		if te.Code != c.code {
			t.Errorf("%s/%v: code %q, want %q", c.param, c.err, te.Code, c.code)
		}
		if !errors.Is(te, c.err) {
			t.Errorf("%s/%v: does not wrap the cause", c.param, c.err)
		}
	}
	if NewTokenParamError(ParamPresentedToken, nil) != nil {
		t.Fatal("nil error classified")
	}
	inner := &TokenError{Code: TokenErrInvalidSubagentToken}
	if got := NewTokenParamError(ParamPresentedToken, inner); got != inner {
		t.Fatalf("existing TokenError rewrapped: %v", got)
	}
}

func TestWriteTokenError(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{NewTokenParamError(ParamPresentedToken, ErrExpired), http.StatusBadRequest, TokenErrExpiredPresentedToken},
		{&TokenError{Code: TokenErrASUnreachable}, http.StatusBadGateway, TokenErrASUnreachable},
		{&TokenError{Code: TokenErrUserUnreachable}, http.StatusForbidden, TokenErrUserUnreachable},
		{errors.New("boom"), http.StatusInternalServerError, TokenErrServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		WriteTokenError(rec, c.err)
		if rec.Code != c.status || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%v: status %d type %q", c.err, rec.Code, rec.Header().Get("Content-Type"))
		}
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != c.code {
			t.Errorf("%v: body %s", c.err, rec.Body.Bytes())
		}
		// A client reads the same code back.
		if te := tokenErrorFrom(rec.Body.Bytes()); te == nil || te.Code != c.code {
			t.Errorf("%v: client decode %v", c.err, te)
		}
	}
}

func TestVerifySubagentToken(t *testing.T) {
	ctx := context.Background()
	parent := testAgent(t, WithIssuer("https://agent.example"))
	// The provider key of each issuer below is the parent's key.
	opts := VerifyAgentTokenOptions{Resolver: StaticResolver{"https://agent.example": parent.JWKS(), "https://other.example": parent.JWKS()}}
	subKey := testAgent(t).Key.Public()
	ptok, err := parent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := VerifyAgentToken(ctx, ptok, opts)
	if err != nil {
		t.Fatal(err)
	}
	subTok, err := parent.IssueSubAgentToken("worker1", subKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySubagentToken(ctx, subTok, signer, opts); err != nil {
		t.Fatalf("valid sub-agent token: %v", err)
	}

	wantCode := func(name string, err error, code string) {
		t.Helper()
		var te *TokenError
		if !errors.As(err, &te) || te.Code != code {
			t.Errorf("%s: err = %v, want %s", name, err, code)
		}
	}
	// A sub-agent token from another agent provider (iss differs).
	other := &Agent{ID: parent.ID, Issuer: "https://other.example", Key: parent.Key, TokenTTL: time.Hour}
	otherTok, err := other.IssueSubAgentToken("worker1", subKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySubagentToken(ctx, otherTok, signer, opts)
	wantCode("iss differs", err, TokenErrInvalidSubagentToken)
	// Not a sub-agent at all.
	_, err = VerifySubagentToken(ctx, ptok, signer, opts)
	wantCode("no parent_agent", err, TokenErrInvalidSubagentToken)
	// parent_agent names someone else.
	strangerID, _ := ParseAgentIdentifier("aauth:stranger@agent.example")
	stranger := &Agent{ID: strangerID, Issuer: parent.Issuer, Key: parent.Key, TokenTTL: time.Hour}
	strangerSub, err := stranger.IssueSubAgentToken("w", subKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySubagentToken(ctx, strangerSub, signer, opts)
	wantCode("parent mismatch", err, TokenErrInvalidSubagentToken)
	// Expired.
	expired := opts
	expired.Signature = fixedClock(time.Now().Add(48 * time.Hour))
	_, err = VerifySubagentToken(ctx, subTok, signer, expired)
	wantCode("expired", err, TokenErrExpiredSubagentToken)
	// A sub-agent cannot sign for another.
	subSigner, err := VerifyAgentToken(ctx, subTok, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySubagentToken(ctx, subTok, subSigner, opts); !errors.Is(err, ErrSubAgentDirect) {
		t.Errorf("sub-agent signer: err = %v, want ErrSubAgentDirect", err)
	}
}
