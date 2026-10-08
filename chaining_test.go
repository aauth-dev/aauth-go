package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRouteDownstream(t *testing.T) {
	ctx := context.Background()
	ps, as, caller := testAgent(t), testAgent(t), testAgent(t)
	const bookingID, asURL = "https://booking.example", "https://as.example"
	now := time.Now()
	// An auth token routes by ps, never by iss (an AS in four-party).
	raw := mintTestAuth(t, as, caller, asURL, bookingID, now, func(c *AuthClaims) {
		c.DWK, c.PS, c.MissionS256 = WellKnownAccess, testPS, "m1"
	})
	auth, err := VerifyUpstreamToken(ctx, raw, UpstreamVerifyOptions{
		TokenVerifyOptions: TokenVerifyOptions{Resolver: StaticResolver{asURL: as.JWKS()}},
		Intermediary:       &AgentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: bookingID}},
		PS:                 testPS, AtAS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := RouteDownstream(auth, raw)
	if err != nil || r.PersonServer != testPS || r.UpstreamToken != raw || r.MissionS256 != "m1" || !r.UpstreamExpiresAt.Equal(now.Add(time.Hour).Truncate(time.Second)) {
		t.Fatalf("auth token route: %+v, %v", r, err)
	}
	// The raw token must be the verified one.
	other := mintTestAuth(t, as, caller, asURL, bookingID, now, func(c *AuthClaims) { c.ID = "other"; c.PS = testPS })
	if _, err := RouteDownstream(auth, other); err == nil {
		t.Error("routed with a different raw token")
	}
	// A person token routes by iss.
	callerJWK := caller.JWK()
	personRaw, person, err := IssuePersonToken(PersonTokenParams{
		Issuer: testPS, Resource: bookingID, Subject: "s1",
		Agent: &AgentClaims{Cnf: Cnf{JWK: &callerJWK}, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}},
	}, ps.Key, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	if r, err = RouteDownstream(person, personRaw); err != nil || r.PersonServer != testPS || r.MissionS256 != "" {
		t.Fatalf("person token route: %+v, %v", r, err)
	}
	// The intermediary must be its own agent provider (§10.1.1.1).
	if _, err := r.Transport(testAgent(t, WithIssuer(bookingID))); err != nil {
		t.Fatalf("own provider: %v", err)
	}
	if _, err := r.Transport(testAgent(t, WithIssuer("https://agents.example"))); err == nil {
		t.Error("an intermediary under another agent provider was accepted")
	}
	var typedNil *AuthClaims
	for name, up := range map[string]PresentedToken{"nil": nil, "typed nil": typedNil, "no ps": &AuthClaims{}} {
		if _, err := RouteDownstream(up, raw); err == nil {
			t.Errorf("%s: routed", name)
		}
	}
	if _, err := RouteDownstream(auth, ""); err == nil {
		t.Error("routed without the raw upstream token")
	}
	// Empty jtis must not associate a raw token with verified claims: a
	// token without jti fails verification, and claims without one are
	// refused before the comparison.
	noJTI := mintTestAuth(t, as, caller, asURL, bookingID, now, func(c *AuthClaims) {
		c.DWK, c.PS, c.ID = WellKnownAccess, testPS, ""
	})
	if _, err := VerifyUpstreamToken(ctx, noJTI, UpstreamVerifyOptions{
		TokenVerifyOptions: TokenVerifyOptions{Resolver: StaticResolver{asURL: as.JWKS()}},
		Intermediary:       &AgentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: bookingID}},
		PS:                 testPS, AtAS: true,
	}); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("verified an upstream token without jti: %v", err)
	}
	if _, err := RouteDownstream(&AuthClaims{PS: testPS}, noJTI); err == nil {
		t.Error("routed claims without jti against a raw token without jti")
	}
}

// TestCallChainingEndToEnd runs §10.1.1: asst holds an auth token for
// booking; booking, acting as an agent that is its own agent provider,
// routes by the upstream token to the person's PS, obtains a person token
// for payments with upstream_token, presents it, and redeems payments'
// resource token at the same PS with the person token as presented_token
// and the upstream token as upstream_token. Payments sees its own
// directed sub, and no downstream token outlives the upstream token.
func TestCallChainingEndToEnd(t *testing.T) {
	asst := testAgent(t)
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	psKey, _ := NewAgent(psID)
	payKey := testAgent(t)

	var psURL, paymentsURL, bookingURL string
	var upstreamSeen atomic.Int32
	resolver := func() StaticResolver { return StaticResolver{psURL: psKey.JWKS(), paymentsURL: payKey.JWKS()} }
	verifyUpstream := func(r *http.Request, caller *AgentClaims, raw string) (PresentedToken, error) {
		upstreamSeen.Add(1)
		return VerifyUpstreamToken(r.Context(), raw, UpstreamVerifyOptions{
			TokenVerifyOptions: localOpts(resolver()), Intermediary: caller, PS: psURL,
		})
	}

	psMux := http.NewServeMux()
	psMux.HandleFunc("POST /person", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var preq PersonTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&preq); err != nil || preq.MissionS256 != "" {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		up, err := verifyUpstream(r, caller, preq.UpstreamToken)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		// The person the upstream token was issued for, with payments'
		// directed sub (§10.1.1.2); bounded by the upstream token.
		tok, pc, err := IssuePersonToken(PersonTokenParams{
			Issuer: psURL, Resource: preq.Resource, Subject: "payments-sub-for-alice", Agent: caller,
			UpstreamExpiresAt: up.(*AuthClaims).ExpiresAt.Time, InsecureSkipIdentifierCheck: true,
		}, psKey.Key, psKey.JWK().Kid)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		writeJSON(t, rw, PersonTokenResponse{PersonToken: tok, ExpiresIn: int64(time.Until(pc.ExpiresAt.Time).Seconds())})
	})
	psMux.HandleFunc("POST /token", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var treq AuthTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&treq); err != nil {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		up, err := verifyUpstream(r, caller, treq.UpstreamToken)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		rc, presented, err := VerifyResourceToken(r.Context(), treq.ResourceToken, ResourceTokenVerifyOptions{
			TokenVerifyOptions: localOpts(resolver()), Audience: psURL, PS: psURL,
			AgentJKT: caller.Cnf.JWK.Thumbprint(), PresentedToken: treq.PresentedToken,
		})
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		tok, ac, err := IssueAuthToken(AuthTokenParams{
			Issuer: psURL, Resource: rc, Presented: presented, Agent: caller, Scope: rc.Scope,
			UpstreamExpiresAt: up.(*AuthClaims).ExpiresAt.Time,
		}, psKey.Key, psKey.JWK().Kid)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		writeJSON(t, rw, AuthTokenResponse{AuthToken: tok, ExpiresIn: int64(time.Until(ac.ExpiresAt.Time).Seconds())})
	})
	ps := httptest.NewServer(psMux)
	t.Cleanup(ps.Close)
	psURL = ps.URL

	w := &threePartyWorld{psAgent: psKey, resourceKey: payKey}
	payments := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.psURL, w.resourceURL = psURL, paymentsURL
		w.serveResource(t, func() string { return paymentsURL }, "charge", nil)(rw, r)
	}))
	t.Cleanup(payments.Close)
	paymentsURL = payments.URL
	bookingURL = "https://booking.example" // booking's resource identifier
	booking := testAgent(t, WithIssuer(bookingURL))

	// 1. asst presents an auth token to booking, valid for 50 minutes.
	asstJWK := asst.JWK()
	upstreamRaw := mintTestAuth(t, psKey, asst, psURL, bookingURL, time.Now().Add(-10*time.Minute), func(c *AuthClaims) {
		c.Cnf = Cnf{JWK: &asstJWK}
		c.Subject = "booking-sub-for-alice"
	})
	// 2. booking verifies it (as the resource that served asst) and routes.
	upstream, err := VerifyAuthToken(context.Background(), upstreamRaw, bookingURL, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(StaticResolver{psURL: psKey.JWKS()})})
	if err != nil {
		t.Fatal(err)
	}
	router, err := RouteDownstream(upstream, upstreamRaw)
	if err != nil || router.PersonServer != psURL {
		t.Fatalf("router %+v, %v", router, err)
	}
	tr, err := router.Transport(booking)
	if err != nil {
		t.Fatal(err)
	}
	tr.ResourceVerify = localOpts(StaticResolver{paymentsURL: payKey.JWKS()})

	// 3. booking calls payments: agent token → person token → auth token.
	resp, err := (&http.Client{Transport: tr}).Get(paymentsURL + "/files")
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello payments-sub-for-alice scope=charge" {
		t.Fatalf("payments: %d %s", resp.StatusCode, body)
	}
	if upstreamSeen.Load() != 2 {
		t.Fatalf("PS verified the upstream token %d times, want 2 (person and auth token requests)", upstreamSeen.Load())
	}
	// No downstream token outlives the upstream one.
	tr.mu.Lock()
	ct := tr.auth[paymentsURL]
	tr.mu.Unlock()
	if ct.exp.After(router.UpstreamExpiresAt) {
		t.Fatalf("downstream auth token exp %v after upstream %v", ct.exp, router.UpstreamExpiresAt)
	}
	// Once the upstream token has expired, the intermediary stops.
	tr2, err := router.Transport(booking)
	if err != nil {
		t.Fatal(err)
	}
	tr2.UpstreamExpiresAt = time.Now().Add(-time.Second)
	if resp, err := (&http.Client{Transport: tr2}).Get(paymentsURL + "/files"); err == nil {
		closeBody(resp.Body)
		t.Fatal("chained with an expired upstream token")
	}

	// An intermediary whose agent token iss is not the upstream aud is
	// refused by the PS too (§10.1.1.1): here, a different agent provider.
	other := testAgent(t, WithIssuer("https://other.example"))
	if _, err := router.PSClient(other).RequestPersonToken(context.Background(), PersonTokenRequest{
		Resource: paymentsURL, UpstreamToken: upstreamRaw,
	}); tokenErrorCode(err) != TokenErrInvalidUpstreamToken {
		t.Fatalf("foreign intermediary: err = %v", err)
	}
}

func TestVerifyUpstreamToken(t *testing.T) {
	ctx := context.Background()
	const intermediaryID = "https://booking.example"
	ps, as := testAgent(t), testAgent(t)
	const asURL = "https://as.example"
	caller := testAgent(t)
	callerJWK := caller.JWK()
	intermediary := &AgentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: intermediaryID}}
	opts := func() UpstreamVerifyOptions {
		return UpstreamVerifyOptions{
			TokenVerifyOptions: TokenVerifyOptions{Resolver: StaticResolver{testPS: ps.JWKS(), asURL: as.JWKS()}},
			Intermediary:       intermediary,
			PS:                 testPS,
		}
	}
	now := time.Now()
	personTok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: testPS, Resource: intermediaryID, Subject: "s1",
		Agent: &AgentClaims{Cnf: Cnf{JWK: &callerJWK}, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}},
	}, ps.Key, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	if up, err := VerifyUpstreamToken(ctx, personTok, opts()); err != nil || up.PersonServer() != testPS {
		t.Fatalf("person upstream: %v, %v", up, err)
	}
	// An auth token from an AS the PS federated with.
	asAuth := mintTestAuth(t, as, caller, asURL, intermediaryID, now, func(c *AuthClaims) { c.DWK = WellKnownAccess; c.PS = testPS })
	if _, err := VerifyUpstreamToken(ctx, asAuth, opts()); tokenErrorCode(err) != TokenErrInvalidUpstreamToken {
		t.Errorf("unrecognized AS issuer at the PS: err = %v", err)
	}
	o := opts()
	o.TrustAuthIssuer = func(iss, aud, sub string) bool { return iss == asURL && aud == intermediaryID && sub == "user-1" }
	if _, err := VerifyUpstreamToken(ctx, asAuth, o); err != nil {
		t.Errorf("trusted AS issuer at the PS: %v", err)
	}
	o = opts()
	o.AtAS = true
	if _, err := VerifyUpstreamToken(ctx, asAuth, o); err != nil {
		t.Errorf("AS-issued upstream at the AS: %v", err)
	}
	// A person token issued by another PS.
	o = opts()
	o.PS = "https://other-ps.example"
	if _, err := VerifyUpstreamToken(ctx, personTok, o); tokenErrorCode(err) != TokenErrInvalidUpstreamToken {
		t.Errorf("other PS: err = %v", err)
	}
	// Not addressed to this intermediary.
	o = opts()
	o.Intermediary = &AgentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://other.example"}}
	if _, err := VerifyUpstreamToken(ctx, personTok, o); tokenErrorCode(err) != TokenErrInvalidUpstreamToken {
		t.Errorf("wrong intermediary: err = %v", err)
	}
	// Expired.
	o = opts()
	o.Signature = fixedClock(now.Add(2 * time.Hour))
	if _, err := VerifyUpstreamToken(ctx, personTok, o); tokenErrorCode(err) != TokenErrExpiredUpstreamToken {
		t.Errorf("expired: err = %v", err)
	}
	// An agent token is not an upstream token.
	agentTok, err := caller.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpstreamToken(ctx, agentTok, opts()); tokenErrorCode(err) != TokenErrInvalidUpstreamToken {
		t.Errorf("agent token: err = %v", err)
	}
}
