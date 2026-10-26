package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Error codes of the authorization endpoint (draft -11 §6.6.3), besides
// [ErrCodeInvalidRequest] and [ErrCodeServerError].
const (
	ErrCodeInvalidScope   = "invalid_scope"   // 400: requested scope not recognized by the resource
	ErrCodeInvalidAccount = "invalid_account" // 400: the account is not held by the person the person token identifies
)

// AuthorizeStatusAuthorized is the status of an authorization endpoint
// response when the resource handled authorization itself (§6.6.1).
const AuthorizeStatusAuthorized = "authorized"

// ErrNoAuthorizationEndpoint means a resource's metadata publishes no
// authorization_endpoint (§6.6, §11.2.4), so the agent cannot ask for
// access ahead of a call; it calls the resource and answers its challenges.
var ErrNoAuthorizationEndpoint = errors.New("aauth: resource publishes no authorization_endpoint")

// AuthorizeRequest is the body of a request to a resource's authorization
// endpoint (draft -11 §6.6). Members a recipient does not recognize are
// ignored, so extensions add members alongside these.
type AuthorizeRequest struct {
	// Scope is the space-separated scope requested (§11.10). REQUIRED.
	Scope string `json:"scope"`
	// Account names the account at the resource the authorization is
	// for, from the resource's own namespace (§11.11).
	Account string `json:"account,omitempty"`
}

// AuthorizeResponse is the 200 body of the authorization endpoint: status
// authorized and the granted scope when the resource handles authorization
// itself (§6.6.1), or a resource token for the agent's PS (§6.6.2).
type AuthorizeResponse struct {
	Status        string `json:"status,omitempty"`
	Scope         string `json:"scope,omitempty"`
	ResourceToken string `json:"resource_token,omitempty"`
}

// AuthorizeResult is the outcome of [Transport.Authorize].
type AuthorizeResult struct {
	// Status is "authorized" when the resource handled authorization
	// itself (§6.6.1), else "".
	Status string
	// Scope is the scope the resource granted, when it handled
	// authorization itself.
	Scope string
	// SessionToken is the AAuth-Access session token the resource issued,
	// if any (§6.3). The transport also caches it for later calls.
	SessionToken string
	// AuthToken is the auth token obtained by redeeming the resource token
	// the resource returned (§6.6.2, §7.2). The transport also caches it
	// for later calls.
	AuthToken string
}

// Authorize requests access to resource for a scope ahead of calling it,
// at the resource's authorization endpoint (draft -11 §6.6), discovered
// from its metadata (§11.2.4). It presents a person token from the PS,
// signed with the agent's key, and then:
//
//   - follows a 202 deferred response (interaction or approval, §6.2) until
//     the resource answers;
//   - on status authorized, returns the granted scope and caches any
//     AAuth-Access session token (§6.6.1, §6.3);
//   - on a resource token, verifies it as a challenge to the person token
//     (§6.7.3), redeems it at the PS (§7.2), checks and caches the auth
//     token, and returns it (§6.6.2).
//
// Tokens it caches are presented by the transport's later requests to the
// resource. Error responses are [*ProblemError]s with a §6.6.3 code
// ([ErrCodeInvalidScope], [ErrCodeInvalidAccount], …).
func (t *Transport) Authorize(ctx context.Context, resource string, req AuthorizeRequest) (*AuthorizeResult, error) {
	switch {
	case t.Agent == nil:
		return nil, errors.New("aauth: Transport.Agent is required")
	case t.PS == nil:
		return nil, fmt.Errorf("aauth: the authorization endpoint requires a person token but Transport.PS is not configured")
	case strings.TrimSpace(req.Scope) == "":
		return nil, errors.New("aauth: AuthorizeRequest.Scope is required (§6.6)")
	}
	resource = strings.TrimSuffix(resource, "/")
	var md ResourceMetadata
	if err := FetchMetadata(ctx, &http.Client{Transport: t.base()}, resource, WellKnownResource, &md); err != nil {
		return nil, err
	}
	if md.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoAuthorizationEndpoint, resource)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("aauth: authorization request: %w", err)
	}
	t.markPerson(resource)
	res, presented, err := t.postAuthorize(ctx, resource, md.AuthorizationEndpoint, body)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	t.observeSession(resource, res)
	b, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes))
	if err != nil {
		return nil, fmt.Errorf("aauth: authorization response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, endpointError("authorization endpoint", res, b)
	}
	var ar AuthorizeResponse
	if err := json.Unmarshal(b, &ar); err != nil {
		return nil, fmt.Errorf("aauth: authorization response: %w", err)
	}
	result := &AuthorizeResult{Status: ar.Status, Scope: ar.Scope, SessionToken: t.cachedSession(resource)}
	switch {
	case ar.ResourceToken != "":
		if result.AuthToken, err = t.authorize(ctx, resource, ar.ResourceToken, presented); err != nil {
			return nil, err
		}
	case ar.Status != AuthorizeStatusAuthorized:
		return nil, fmt.Errorf("aauth: authorization response from %s has neither status authorized nor a resource_token", resource)
	}
	return result, nil
}

// postAuthorize sends the signed authorization request with a person token
// and follows deferred responses. A refused person token (requirement
// person-token, or 401 expired_jwt or revoked_jwt) is replaced once.
func (t *Transport) postAuthorize(ctx context.Context, resource, endpoint string, body []byte) (*http.Response, string, error) {
	for attempt := 0; ; attempt++ {
		person, err := t.personToken(ctx, resource)
		if err != nil {
			return nil, "", err
		}
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, "", fmt.Errorf("aauth: authorization request: %w", err)
		}
		hreq.Header.Set("Content-Type", "application/json")
		signed, presented, err := t.sign(hreq, body, person, t.cachedSession(resource))
		if err != nil {
			return nil, "", err
		}
		res, err := t.base().RoundTrip(signed)
		if err != nil {
			return nil, "", err
		}
		if res, err = t.followDeferred(hreq, res, resource, presented); err != nil {
			return nil, "", err
		}
		if res.StatusCode != http.StatusUnauthorized || attempt > 0 || !t.personRefused(res, resource) {
			return res, presented, nil
		}
		drainBody(res.Body)
	}
}

// personRefused reports whether a 401 refused the person token, dropping it
// from the PS cache so the next attempt obtains a fresh one.
func (t *Transport) personRefused(res *http.Response, resource string) bool {
	if r, err := ParseRequirement(res.Header.Get(HeaderRequirement)); err == nil && r.Requirement == RequirementPersonToken {
		t.PS.ForgetPersonTokens(resource)
		return true
	}
	se, err := SignatureErrorFromResponse(res)
	if err != nil || se == nil || (se.Code != SigErrExpiredJWT && se.Code != SigErrRevokedJWT) {
		return false
	}
	t.PS.ForgetPersonTokens(resource)
	return true
}

// AuthorizeDecision is a resource's answer to a verified authorization
// request (draft -11 §6.6). Set exactly one of Scope (with an optional
// SessionToken), ResourceToken, or Pending.
type AuthorizeDecision struct {
	// Scope is the granted scope when the resource handles authorization
	// itself (§6.6.1). SessionToken, if set, is sent as AAuth-Access (§6.3).
	Scope        string
	SessionToken string
	// ResourceToken is a resource token for the agent's PS or the
	// resource's AS (§6.6.2), from [IssueResourceToken] with the verified
	// person claims as the presented token.
	ResourceToken string
	// Pending defers the request for user interaction (§6.2, §6.6.1): the
	// handler answers 202 with requirement=interaction, and the resource
	// later answers polls of Pending.Location, for example with
	// [WriteAuthorized].
	Pending *PendingInteraction
}

// PendingInteraction is a deferred authorization awaiting the user (§6.2,
// §11.6.3).
type PendingInteraction struct {
	Location       string // the resource's pending URL the agent polls
	InteractionURL string // where the user goes
	Code           string // the interaction code shown to the user
}

// AuthorizationHandler serves a resource's authorization endpoint (draft
// -11 §6.6). It accepts POST with a JSON body, verifies the person token
// and the request signature (§7.1.4, with the body covered by a digest),
// and asks Decide. Person tokens are accepted only from issuers
// TrustIssuer accepts. Requests without a person token are answered with
// requirement=person-token (§6.4); failed verification with 401 and
// Signature-Error (§6.6.3).
//
// Decide errors that are [*ProblemError]s are written as they are (for
// example invalid_scope, invalid_account); any other error is server_error.
// A Pending decision is answered with 202 only when the agent declared the
// interaction capability (§11.7); otherwise the handler answers 403 with
// user_unreachable, as a PS does when it cannot reach the person.
type AuthorizationHandler struct {
	// Resource is the resource's own identifier, the person token's aud.
	Resource string
	// Verify configures person token verification.
	Verify TokenVerifyOptions
	// TrustIssuer decides whether the endpoint accepts person tokens from
	// the person server iss, before its keys are resolved; a valid
	// signature proves only that iss signed the token. A refused issuer is
	// answered 403. Required: without it every request is answered 500.
	// See [TrustIssuers].
	TrustIssuer func(ctx context.Context, iss string) error
	// Decide decides on a verified request.
	Decide func(ctx context.Context, r *http.Request, person *PersonClaims, req AuthorizeRequest) (AuthorizeDecision, error)
}

// ServeHTTP implements http.Handler.
func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		WriteProblem(w, http.StatusMethodNotAllowed, ErrCodeInvalidRequest, "the authorization endpoint accepts POST")
		return
	}
	if tok, err := ParseSignatureKey(r); err != nil {
		if errors.Is(err, ErrMissingSigKey) {
			ChallengePersonToken(w)
			return
		}
		WriteSignatureFailure(w, err)
		return
	} else if typ, err := TokenType(tok); err != nil || typ != TypPerson {
		// §6.6: the agent MUST present a person token; anything else is
		// answered per §6.4.
		ChallengePersonToken(w)
		return
	}
	if h.TrustIssuer == nil {
		WriteProblem(w, http.StatusInternalServerError, ErrCodeServerError, "AuthorizationHandler.TrustIssuer is not set")
		return
	}
	opts := h.Verify
	opts.Signature.RequireBodyCoverage = true
	opts.trust = func(ctx context.Context, iss, _ string) error { return h.TrustIssuer(ctx, iss) }
	person, err := VerifyAndExtractPerson(r.Context(), r, h.Resource, opts)
	if errors.Is(err, ErrUntrustedIssuer) {
		WriteProblem(w, http.StatusForbidden, ErrCodeInvalidRequest, err.Error())
		return
	}
	if err != nil {
		WriteSignatureFailure(w, err)
		return
	}
	var req AuthorizeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxDocumentBytes)).Decode(&req); err != nil {
		WriteProblem(w, http.StatusBadRequest, ErrCodeInvalidRequest, "body is not a JSON authorization request")
		return
	}
	if strings.TrimSpace(req.Scope) == "" {
		WriteProblem(w, http.StatusBadRequest, ErrCodeInvalidRequest, "scope is required")
		return
	}
	d, err := h.Decide(r.Context(), r, person, req)
	if err != nil {
		var pe *ProblemError
		if errors.As(err, &pe) {
			WriteProblem(w, pe.Status, pe.Code, pe.Detail)
			return
		}
		WriteProblem(w, http.StatusInternalServerError, ErrCodeServerError, "")
		return
	}
	switch {
	case d.ResourceToken != "":
		writeJSONStatus(w, http.StatusOK, AuthorizeResponse{ResourceToken: d.ResourceToken})
	case d.Pending != nil:
		if !CanRaise(r, RequirementInteraction) {
			WriteProblem(w, http.StatusForbidden, TokenErrUserUnreachable, "user interaction is required and the agent did not declare the interaction capability")
			return
		}
		ChainInteraction(w, d.Pending.Location, d.Pending.InteractionURL, d.Pending.Code)
	default:
		WriteAuthorized(w, d.Scope, d.SessionToken)
	}
}

// WriteAuthorized writes the §6.6.1 response for authorization the resource
// handled itself: 200, status authorized and the granted scope, and the
// session token as AAuth-Access when sessionToken is not empty (§6.3). It
// also answers the final poll of a deferred authorization.
func WriteAuthorized(w http.ResponseWriter, scope, sessionToken string) {
	if sessionToken != "" {
		w.Header().Set(HeaderAAuthAccess, sessionToken)
	}
	writeJSONStatus(w, http.StatusOK, AuthorizeResponse{Status: AuthorizeStatusAuthorized, Scope: scope})
}

// writeJSONStatus writes v as a JSON response with status.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(v)
}
