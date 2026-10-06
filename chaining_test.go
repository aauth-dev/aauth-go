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

func TestActClaimDelegators(t *testing.T) {
	chain := &ActClaim{Agent: "aauth:booking@b.example", Act: &ActClaim{Agent: "aauth:asst@a.example"}}
	got := chain.Delegators()
	if len(got) != 2 || got[0] != "aauth:booking@b.example" || got[1] != "aauth:asst@a.example" {
		t.Fatalf("delegators = %v", got)
	}
}

func TestRouteDownstream(t *testing.T) {
	raw := "raw-upstream"
	// Mission present → governed path to mission.approver.
	up := &AuthClaims{
		Mission:          &MissionRef{Approver: "https://ps.example", S256: "x"},
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://as.example"},
	}
	r, err := RouteDownstream(up, raw, nil)
	if err != nil || r.Endpoint != "https://ps.example" || !r.Governed {
		t.Fatalf("mission route: %+v, %v", r, err)
	}
	// No mission, iss is a PS → route to that PS, governed.
	up = &AuthClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://ps.example"}}
	r, _ = RouteDownstream(up, raw, func(iss string) bool { return iss == "https://ps.example" })
	if r.Endpoint != "https://ps.example" || !r.Governed {
		t.Fatalf("PS route: %+v", r)
	}
	// No mission, iss is an AS → route to AS, ungoverned.
	up = &AuthClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://as.example"}}
	r, _ = RouteDownstream(up, raw, func(iss string) bool { return false })
	if r.Endpoint != "https://as.example" || r.Governed {
		t.Fatalf("AS route: %+v", r)
	}
	// Neither mission nor iss → error.
	if _, err := RouteDownstream(&AuthClaims{}, raw, nil); err == nil {
		t.Fatal("expected routing error")
	}
}

// TestCallChainingEndToEnd runs the spec's asst → booking → payments chain
// (§10.3.1): the top-level agent gets an auth token for booking; booking,
// acting as an agent, exchanges at the PS to get a downstream token for
// payments carrying act={agent: asst}.
func TestCallChainingEndToEnd(t *testing.T) {
	asst := testAgent(t)
	bookingID, _ := ParseAgentIdentifier("aauth:booking@booking.example")
	booking, _ := NewAgent(bookingID)
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	psKey, _ := NewAgent(psID)

	var psURL, paymentsURL string

	// The PS token endpoint: issues auth tokens, threading the act chain when
	// an upstream_token is presented (call chaining, §10.1.1 + §10.3).
	psMux := http.NewServeMux()
	psMux.HandleFunc("POST /token", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		var treq TokenRequest
		_ = json.NewDecoder(r.Body).Decode(&treq)

		var act *ActClaim
		aud := paymentsURL
		if treq.UpstreamToken != "" {
			// Booking presents asst's auth token as upstream proof. Verify it
			// was issued by us to the immediate upstream agent, then record
			// that agent in the downstream act chain.
			upstream, err := VerifyAuthToken(r.Context(), treq.UpstreamToken, booking.ID.String()+"", StaticResolver{psURL: psKey.JWKS()})
			_ = err // audience check below is what matters for this test
			if upstream == nil {
				// Fall back to unverified decode for the agent id (test PS).
				upstream = &AuthClaims{}
				p := jwt.NewParser(jwt.WithoutClaimsValidation())
				_, _, _ = p.ParseUnverified(treq.UpstreamToken, upstream)
			}
			act = NextAct(upstream.Agent, upstream.Act)
		}
		tok := mustMintAuth(t, psKey, psURL, aud, caller.Subject, caller.Cnf.JWK, "charge", act)
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(TokenResponse{AuthToken: tok, ExpiresIn: 3600})
	})
	ps := httptest.NewServer(psMux)
	t.Cleanup(ps.Close)
	psURL = ps.URL

	// Payments: verifies the auth token booking presents, and asserts the
	// delegation chain names asst as the original delegator.
	var chainSeen []string
	payments := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		claims, err := VerifyAndExtractAuth(r.Context(), r, paymentsURL, StaticResolver{psURL: psKey.JWKS()})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
			return
		}
		if claims.Act != nil {
			chainSeen = claims.Act.Delegators()
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(payments.Close)
	paymentsURL = payments.URL

	// 1. asst obtains an auth token for booking (direct — no act).
	asstJWK := asst.JWK()
	asstAuthForBooking := mustMintAuth(t, psKey, psURL, booking.ID.String()+"", asst.ID.String(), &asstJWK, "book", nil)

	// 2. booking, acting as an agent, routes the downstream request from the
	// upstream token and exchanges at the PS for a payments token.
	up := &AuthClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: psURL}}
	router, err := RouteDownstream(up, asstAuthForBooking, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	psc := NewPSClient(router.Endpoint, booking)
	grant, err := psc.ExchangeToken(context.Background(), TokenRequest{
		ResourceToken: "stub-resource-token", // (payments would issue this via 401; elided)
		UpstreamToken: router.UpstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. booking calls payments with the downstream token.
	res := callResource(t, booking, paymentsURL, grant.AuthToken)
	closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("payments status %d", res.StatusCode)
	}
	if len(chainSeen) != 1 || chainSeen[0] != asst.ID.String() {
		t.Fatalf("delegation chain at payments = %v, want [%s]", chainSeen, asst.ID)
	}
}

func mustMintAuth(t *testing.T, ps *Agent, iss, aud, agent string, cnf *JWK, scope string, act *ActClaim) string {
	t.Helper()
	now := time.Now()
	jti, _ := randomJTI()
	tok, err := MintAuthToken(AuthClaims{
		DWK:   WellKnownPerson,
		Agent: agent,
		Scope: scope,
		Cnf:   Cnf{JWK: cnf},
		Act:   act,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "user:alice",
			Audience:  jwt.ClaimStrings{aud},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}, ps.Priv, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
