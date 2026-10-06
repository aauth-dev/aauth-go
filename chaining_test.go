package aauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRouteDownstream(t *testing.T) {
	const raw = "eyJ.upstream.token"
	// An auth token routes by ps, never by iss (an AS in four-party).
	auth := &AuthClaims{PS: "https://ps.example", MissionS256: "m1", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://as.example"}}
	r, err := RouteDownstream(auth, raw)
	if err != nil || r.PersonServer != "https://ps.example" || r.UpstreamToken != raw || r.MissionS256 != "m1" {
		t.Fatalf("auth token route: %+v, %v", r, err)
	}
	// A person token routes by iss.
	person := &PersonClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://ps.example"}}
	if r, err = RouteDownstream(person, raw); err != nil || r.PersonServer != "https://ps.example" || r.MissionS256 != "" {
		t.Fatalf("person token route: %+v, %v", r, err)
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
}

// TestCallChainingEndToEnd runs §10.1.1: asst holds an auth token for
// booking; booking, acting as an agent that is its own agent provider,
// routes by the upstream token to the person's PS, which verifies the
// upstream token (§9.4.5) and issues a downstream auth token for payments
// with payments' own directed sub.
func TestCallChainingEndToEnd(t *testing.T) {
	const bookingID = "https://booking.example" // booking's resource identifier
	asst := testAgent(t)
	booking := testAgent(t, WithIssuer(bookingID))
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	psKey, _ := NewAgent(psID)

	var psURL, paymentsURL string
	var sawUpstream PresentedToken

	psMux := http.NewServeMux()
	psMux.HandleFunc("POST /token", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var treq TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&treq); err != nil {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		up, err := VerifyUpstreamToken(r.Context(), treq.UpstreamToken, UpstreamVerifyOptions{
			TokenVerifyOptions: localOpts(StaticResolver{psURL: psKey.JWKS()}),
			Intermediary:       caller,
			PS:                 psURL,
		})
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		sawUpstream = up
		// The downstream sub is payments' directed identifier, not the
		// upstream sub (§10.1.1.2).
		tok := mustMintAuth(t, psKey, psURL, paymentsURL, "payments-sub-for-alice", caller.Cnf.JWK, "charge")
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(TokenResponse{AuthToken: tok, ExpiresIn: 3600})
	})
	ps := httptest.NewServer(psMux)
	t.Cleanup(ps.Close)
	psURL = ps.URL

	payments := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		claims, err := VerifyAndExtractAuth(r.Context(), r, paymentsURL, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(StaticResolver{psURL: psKey.JWKS()})})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		writeBody(t, rw, "%s", claims.Subject)
	}))
	t.Cleanup(payments.Close)
	paymentsURL = payments.URL

	// 1. asst holds an auth token for booking.
	asstJWK := asst.JWK()
	asstAuthForBooking := mustMintAuth(t, psKey, psURL, bookingID, "booking-sub-for-alice", &asstJWK, "book")

	// 2. booking verifies it (as the resource that served asst) and routes
	// the downstream request by its ps.
	upstream, err := VerifyAuthToken(context.Background(), asstAuthForBooking, bookingID, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(StaticResolver{psURL: psKey.JWKS()})})
	if err != nil {
		t.Fatal(err)
	}
	router, err := RouteDownstream(upstream, asstAuthForBooking)
	if err != nil {
		t.Fatal(err)
	}
	if router.PersonServer != psURL {
		t.Fatalf("routed to %q, want %q", router.PersonServer, psURL)
	}
	psc := NewPSClient(router.PersonServer, booking)
	grant, err := psc.ExchangeToken(context.Background(), TokenRequest{
		ResourceToken: "stub-resource-token", // (payments would issue this via 401; elided)
		UpstreamToken: router.UpstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ac, ok := sawUpstream.(*AuthClaims); !ok || ac.Subject != "booking-sub-for-alice" {
		t.Fatalf("PS saw upstream %#v", sawUpstream)
	}

	// 3. booking calls payments with the downstream token.
	res := callResource(t, booking, paymentsURL, grant.AuthToken)
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("payments status %d", res.StatusCode)
	}

	// An intermediary whose agent token iss is not the upstream aud is
	// refused (§10.1.1.1): here, a different agent provider.
	other := testAgent(t, WithIssuer("https://other.example"))
	if _, err := NewPSClient(psURL, other).ExchangeToken(context.Background(), TokenRequest{
		ResourceToken: "stub-resource-token", UpstreamToken: asstAuthForBooking,
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

func mustMintAuth(t *testing.T, ps *Agent, iss, aud, sub string, cnf *JWK, scope string) string {
	t.Helper()
	now := time.Now()
	jti, _ := randomJTI()
	tok, err := MintAuthToken(AuthClaims{
		DWK:   WellKnownPerson,
		PS:    iss,
		Scope: scope,
		Cnf:   Cnf{JWK: cnf},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}, ps.Key, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
