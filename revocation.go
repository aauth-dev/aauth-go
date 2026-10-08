package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Token revocation (draft -11 §11.12). A PS, an AS, and a resource that
// accepts person tokens SHOULD publish a revocation_endpoint; a server
// without one honors a revoked token until its exp. The caller signs as a
// server under the jwks_uri scheme ([ServerSigner], §11.3.2) with
// content-digest and content-type covered, and names the token by jti
// within its own namespace: the issuer is the verified signer, so a caller
// revokes only its own tokens, and recipients key revocation state by
// (iss, jti).
//
// Who revokes what (§11.12.2):
//
//	Token     Revoked by                          At
//	agent     the agent provider that issued it    the PS only
//	person    the PS that issued it                the resource in its aud, and each AS
//	                                               the PS presented it to
//	auth      the PS (three-party) or AS           the resource it was issued for; a PS
//	          (four-party) that issued it          that federated revokes the person token
//	                                               at the AS instead
//	resource  the resource that issued it          the party in its aud, and in four-party
//	                                               the ps as well
//
// The recipient records the revocation, revokes downstream (§11.12.4), and
// answers 200 once every downstream revocation has a terminal outcome, or
// 202 to be polled when that takes longer. There is no "not found".

// Downstream revocation outcomes reported in a [RevocationResponse]
// (§11.12.3).
const (
	// RevocationUnsupported: the downstream party publishes no
	// revocation_endpoint or answered unsupported_iss; it honors the tokens
	// until their exp.
	RevocationUnsupported = "revocation_unsupported"
	// RevocationUnavailable: the downstream party did not respond, timed
	// out, or returned a 5xx or malformed response; the caller MAY revoke
	// again later.
	RevocationUnavailable = "revocation_unavailable"
)

// ErrRevocationUnsupported means the recipient publishes no
// revocation_endpoint, or does not accept revocations from this caller
// (unsupported_iss): it honors the token until its exp.
var ErrRevocationUnsupported = errors.New("aauth: " + RevocationUnsupported)

// ErrRevocationUnavailable means a revocation reached no terminal outcome:
// no response, a timeout, a 5xx, or a malformed body. It may be retried.
var ErrRevocationUnavailable = errors.New("aauth: " + RevocationUnavailable)

// RevocationRequest is the body of POST {revocation_endpoint} (draft -11
// §11.12.1).
type RevocationRequest struct {
	// JTI names the token to revoke within the caller's namespace.
	// REQUIRED.
	JTI string `json:"jti"`
	// Exp is the revoked token's own exp (seconds since the epoch), which
	// bounds how long the recipient remembers the revocation. REQUIRED.
	Exp int64 `json:"exp"`
}

// Validate checks the REQUIRED members; a recipient answers a failure with
// 400 invalid_request.
func (r RevocationRequest) Validate() error {
	switch {
	case r.JTI == "":
		return errors.New("aauth: revocation request has no jti")
	case r.Exp <= 0:
		return errors.New("aauth: revocation request has no valid exp")
	}
	return nil
}

// RevocationOutcome is one entry of a [RevocationResponse]'s downstream
// array: the recipient revoked at, and an error when that revocation did
// not succeed.
type RevocationOutcome struct {
	Recipient string `json:"recipient"`       // the downstream party's identifier
	Error     string `json:"error,omitempty"` // RevocationUnsupported or RevocationUnavailable
}

// RevocationResponse is the body of a 200 revocation response (§11.12.3).
// An AS reports the resources it revoked at to the PS; other recipients
// answer with an empty body, which decodes to the zero value.
type RevocationResponse struct {
	Downstream []RevocationOutcome `json:"downstream,omitempty"`
}

// RevocationClient revokes tokens a server issued, at another server's
// revocation endpoint (draft -11 §11.12).
type RevocationClient struct {
	// Signer signs the revocation and its polls under the jwks_uri scheme
	// (§11.3.2). Required.
	Signer ServerSigner
	// HTTPClient makes requests; nil uses [DiscoveryClient], which reaches
	// only public https destinations: the endpoint comes from the
	// recipient's metadata.
	HTTPClient *http.Client
	// PreferWaitSeconds, when positive, is sent as Prefer: wait=N: how
	// long the caller will wait for the cascade before a 202.
	PreferWaitSeconds int
}

// Revoke posts req to endpoint and returns the terminal outcome, polling
// the pending URL with signed GETs under the same identity when the
// recipient answers 202 (§11.12.3). Failures are a [*ProblemError] —
// invalid_request, unsupported_iss (403; also matches
// [ErrRevocationUnsupported]), rate_limited (429, with RetryAfter), or
// server_error — or an error wrapping [ErrRevocationUnavailable] for a
// response body that is not a JSON object. [RevocationOutcomeFor] maps any
// result to the outcome a cascading caller reports.
func (c *RevocationClient) Revoke(ctx context.Context, endpoint string, req RevocationRequest) (*RevocationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, ErrRevocationUnsupported
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if c.PreferWaitSeconds > 0 {
		hreq.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", c.PreferWaitSeconds))
	}
	if err := c.Signer.SignRequest(hreq); err != nil {
		return nil, fmt.Errorf("aauth: sign revocation: %w", err)
	}
	res, err := DoDeferred(ctx, discoveryClient(c.HTTPClient), hreq, DeferredOptions{
		PreferWaitSeconds: c.PreferWaitSeconds,
		Sign:              c.Signer.SignRequest,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, revocationError(res)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	var out RevocationResponse
	if len(bytes.TrimSpace(raw)) == 0 {
		return &out, nil // recorded, nothing reported
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		// A non-empty body the caller cannot parse reads as unavailable.
		return nil, fmt.Errorf("%w: response body: %w", ErrRevocationUnavailable, err)
	}
	return &out, nil
}

// revocationError classifies a non-200 terminal revocation response.
func revocationError(res *http.Response) error {
	err := endpointError("revocation endpoint", res, readErrorBody(res))
	var pe *ProblemError
	if !errors.As(err, &pe) && res.StatusCode >= 500 {
		return fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	return err
}

// RevocationOutcomeFor maps the result of revoking at recipient to the
// outcome a recipient reports downstream (§11.12.3): no error is success;
// no revocation_endpoint or unsupported_iss is revocation_unsupported;
// anything else — no response, a timeout, a 5xx, a malformed response,
// rate limiting — is revocation_unavailable.
func RevocationOutcomeFor(recipient string, err error) RevocationOutcome {
	switch {
	case err == nil:
		return RevocationOutcome{Recipient: recipient}
	case errors.Is(err, ErrRevocationUnsupported):
		return RevocationOutcome{Recipient: recipient, Error: RevocationUnsupported}
	}
	return RevocationOutcome{Recipient: recipient, Error: RevocationUnavailable}
}

// RevocationEndpoint discovers the revocation_endpoint of the server
// issuer from its metadata document dwk (draft -11 §11.2.2–§11.2.4),
// verifying the document's issuer. A server that publishes none answers
// [ErrRevocationUnsupported].
func RevocationEndpoint(ctx context.Context, hc *http.Client, issuer, dwk string) (string, error) {
	var md struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := FetchMetadata(ctx, hc, issuer, dwk, &md); err != nil {
		return "", err
	}
	if md.RevocationEndpoint == "" {
		return "", fmt.Errorf("%w: %s publishes no revocation_endpoint", ErrRevocationUnsupported, issuer)
	}
	return md.RevocationEndpoint, nil
}

// ParseRevocationRequest decodes and validates a revocation request body
// (recipient side, §11.12.1). Failures are a [*ProblemError]
// invalid_request (400). The caller has already verified the signature
// with [VerifyServerRequest] (RequireBodyCoverage set): the verified
// caller's ID is the iss the revocation is keyed under.
func ParseRevocationRequest(r *http.Request) (*RevocationRequest, error) {
	var req RevocationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxDocumentBytes)).Decode(&req); err != nil {
		return nil, &ProblemError{Status: http.StatusBadRequest, Code: ErrCodeInvalidRequest, Detail: err.Error()}
	}
	if err := req.Validate(); err != nil {
		return nil, &ProblemError{Status: http.StatusBadRequest, Code: ErrCodeInvalidRequest, Detail: err.Error()}
	}
	return &req, nil
}
