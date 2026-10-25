package walkthrough_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// documents is a resource that requires an auth token. Its resource
// tokens are addressed to audience: the agent's person server
// (three-party) or the access server the resource chose (four-party).
type documents struct {
	url      string
	audience string
	key      crypto.Signer
	jwk      aauth.JWK
	verify   aauth.TokenVerifyOptions
}

func newDocumentsResource(t *testing.T, w *world, audience string) *documents {
	t.Helper()
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	d := &documents{audience: audience, key: key, jwk: jwk, verify: w.verify}
	d.url = serve(t, d)
	return d
}

func (d *documents) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/" + aauth.WellKnownResource:
		respondJSON(w, aauth.ResourceMetadata{
			ServerMetadata:        aauth.ServerMetadata{Issuer: d.url, JWKSURI: d.url + "/jwks"},
			AccessMode:            aauth.AccessModeAuthToken,
			AuthorizationEndpoint: d.url + "/authorize",
		})
	case "/jwks":
		respondJSON(w, aauth.JWKS{Keys: []aauth.JWK{d.jwk}})
	case "/authorize":
		d.authorizationEndpoint().ServeHTTP(w, r)
	default:
		d.serveAPI(w, r)
	}
}

// authorizationEndpoint answers authorization requests with a resource
// token.
func (d *documents) authorizationEndpoint() http.Handler {
	// pidl:begin ps-authorization.authorize.resource
	// The handler verifies the person token and the request signature,
	// then asks Decide. The resource token it returns names the server
	// that decides: the agent's PS, or this resource's access server.
	return &aauth.AuthorizationHandler{
		Resource: d.url,
		Verify:   d.verify, // the PS's keys, discovered from its metadata
		Decide: func(_ context.Context, _ *http.Request, person *aauth.PersonClaims, ar aauth.AuthorizeRequest) (aauth.AuthorizeDecision, error) {
			if ar.Scope != "documents:read" {
				return aauth.AuthorizeDecision{}, &aauth.ProblemError{Status: http.StatusBadRequest, Code: aauth.ErrCodeInvalidScope}
			}
			rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{
				Resource: d.url, Audience: d.audience, Scope: ar.Scope,
			}, person, d.key, d.jwk.Kid)
			return aauth.AuthorizeDecision{ResourceToken: rt}, err
		},
	}
	// pidl:end ps-authorization.authorize.resource
}

// serveAPI serves the documents to a request presenting an auth token.
func (d *documents) serveAPI(w http.ResponseWriter, r *http.Request) {
	// pidl:begin ps-authorization.api-request.resource
	claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, d.url, aauth.AuthTokenVerifyOptions{
		TokenVerifyOptions: d.verify,
		// Accept tokens only from the server this resource's tokens name,
		// and key the person's record by (iss, sub).
		CheckSubject: func(_ context.Context, iss, _ string) error {
			if iss != d.audience {
				return fmt.Errorf("%w: unexpected issuer %s", aauth.ErrInvalidToken, iss)
			}
			return nil
		},
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err) // 401 with Signature-Error
		return
	}
	if !strings.Contains(" "+claims.Scope+" ", " documents:read ") {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeInvalidScope, "documents:read is required")
		return
	}
	respondJSON(w, map[string]any{"owner": claims.Subject, "documents": []string{"plan.md", "notes.md"}})
	// pidl:end ps-authorization.api-request.resource
}

// authorizeAndCall is the agent side of PS authorization: get a person
// token, ask the resource for authorization, redeem the resource token at
// the PS, and call the API with the auth token. It returns the API body.
func authorizeAndCall(t *testing.T, w *world, agent *aauth.Agent, psc *aauth.PSClient, res *documents) string {
	t.Helper()
	ctx, hc := w.ctx, w.hc
	personToken := personToken(t, w, psc, res.url)

	// pidl:begin ps-authorization.authorize.agent
	body, err := json.Marshal(aauth.AuthorizeRequest{Scope: "documents:read"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, res.url+"/authorize", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	aauth.AttachSignatureKey(req, personToken) // present the person token
	if err := aauth.SignRequest(req, agent.Key, ""); err != nil {
		t.Fatal(err) // signs with a Content-Digest of the body
	}
	authRes, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end ps-authorization.authorize.agent
	defer closeBody(t, authRes)

	// pidl:begin ps-authorization.resource-token.agent
	var ar aauth.AuthorizeResponse
	if authRes.StatusCode != http.StatusOK {
		t.Fatalf("authorize: %s", authRes.Status)
	}
	if err := json.NewDecoder(authRes.Body).Decode(&ar); err != nil {
		t.Fatal(err)
	}
	// Check the resource token before sending it to the PS: issued by
	// this resource, for this agent's key, this PS and this person.
	rc, err := aauth.VerifyResourceChallenge(ctx, ar.ResourceToken, aauth.ResourceChallengeOptions{
		TokenVerifyOptions: w.verify, Resource: res.url, Agent: agent, PS: agent.PS, Presented: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end ps-authorization.resource-token.agent

	// pidl:begin ps-authorization.auth-token-request.agent
	// Redeem the resource token with the token presented to get it, and
	// say the agent can bring the person in. The call follows 202
	// responses while the person decides.
	at, err := psc.RequestAuthToken(ctx, aauth.AuthTokenRequest{
		ResourceToken:     ar.ResourceToken,
		PresentedToken:    personToken,
		TokenRequestHints: aauth.TokenRequestHints{Capabilities: []string{aauth.CapabilityInteraction}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end ps-authorization.auth-token-request.agent

	// pidl:begin ps-authorization.auth-token.agent
	// Check the auth token before presenting it: issued by the server the
	// resource token named, for this resource, bound to this agent's key.
	granted, err := aauth.VerifyAuthTokenResponse(ctx, at.AuthToken, aauth.AuthResponseVerifyOptions{
		TokenVerifyOptions: w.verify, Resource: rc, Agent: agent, Presented: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("granted %q until %v", granted.Scope, granted.ExpiresAt)
	// pidl:end ps-authorization.auth-token.agent

	// pidl:begin ps-authorization.api-request.agent
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, res.url+"/api/documents", nil)
	if err != nil {
		t.Fatal(err)
	}
	aauth.AttachSignatureKey(req, at.AuthToken) // present the auth token
	if err := aauth.SignRequest(req, agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	apiRes, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end ps-authorization.api-request.agent
	return readOK(t, apiRes)
}

func TestPSAuthorization(t *testing.T) {
	w := newWorld(t)
	res := newDocumentsResource(t, w, w.psURL) // three-party: the PS decides
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	got := authorizeAndCall(t, w, agent, psc, res)
	if !strings.Contains(got, "plan.md") {
		t.Fatalf("API response %s", got)
	}
}

// respondJSON writes v as a JSON response. The status line is already
// sent when encoding fails, so the failure is logged.
func respondJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writing response", "error", err)
	}
}

// closeBody closes a response body, reporting a failure to the test.
func closeBody(t *testing.T, res *http.Response) {
	if err := res.Body.Close(); err != nil {
		t.Error(err)
	}
}

// readOK returns the body of a 200 response, failing the test otherwise.
func readOK(t *testing.T, res *http.Response) string {
	t.Helper()
	defer closeBody(t, res)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %s: %s", res.Status, b)
	}
	return string(b)
}
