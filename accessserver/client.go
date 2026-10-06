package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/personserver"
)

// Client is the PS side of PS-AS federation over HTTP (draft -11
// §9.1.1): a [personserver.Federator] that signs every request as the PS
// under the jwks_uri scheme (§11.3.2), discovers each access server's
// auth_token_endpoint from /.well-known/aauth-access.json, and maps its
// responses. Configure a PS with it:
//
//	ps, _ := personserver.New(personserver.Config{..., Federator: accessserver.NewClient(psSigner, hc)})
type Client struct {
	// Signer signs as the PS (DWK aauth-person.json). Required.
	Signer aauth.ServerSigner
	// HTTPClient makes requests; nil uses http.DefaultClient. Apply
	// egress admission: the access server is named by a resource token.
	HTTPClient *http.Client
	// PreferWaitSeconds, when positive, is sent as Prefer: wait=N.
	PreferWaitSeconds int

	mu        sync.Mutex
	endpoints map[string]string
}

// NewClient returns a Client signing with signer.
func NewClient(signer aauth.ServerSigner, hc *http.Client) *Client {
	return &Client{Signer: signer, HTTPClient: hc}
}

var _ personserver.Federator = (*Client)(nil)

func (c *Client) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// endpoint discovers and caches the access server's auth token endpoint.
func (c *Client) endpoint(ctx context.Context, as string) (string, error) {
	c.mu.Lock()
	ep, ok := c.endpoints[as]
	c.mu.Unlock()
	if ok {
		return ep, nil
	}
	var md aauth.AccessServerMetadata
	if err := aauth.FetchMetadata(ctx, c.client(), as, aauth.WellKnownAccess, &md); err != nil {
		return "", err
	}
	if err := md.Validate(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.endpoints == nil {
		c.endpoints = map[string]string{}
	}
	c.endpoints[as] = md.AuthTokenEndpoint
	return md.AuthTokenEndpoint, nil
}

// Federate implements personserver.Federator.
func (c *Client) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	ep, err := c.endpoint(ctx, r.AccessServer)
	if err != nil {
		return nil, err
	}
	res, req, err := c.send(ctx, http.MethodPost, ep, r)
	if err != nil {
		return nil, err
	}
	return parseResponse(req.URL, res)
}

// Poll implements personserver.Federator: a signed GET of the pending URL.
func (c *Client) Poll(ctx context.Context, pendingURL string) (*personserver.FederationResponse, error) {
	res, req, err := c.send(ctx, http.MethodGet, pendingURL, nil)
	if err != nil {
		return nil, err
	}
	return parseResponse(req.URL, res)
}

// Answer implements personserver.Federator: a signed POST of body to the
// pending URL.
func (c *Client) Answer(ctx context.Context, pendingURL string, body any) error {
	res, _, err := c.send(ctx, http.MethodPost, pendingURL, body)
	if err != nil {
		return err
	}
	defer drain(res)
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("accessserver: answer status %d: %s", res.StatusCode, b)
	}
	return nil
}

// send makes one signed request as the PS.
func (c *Client) send(ctx context.Context, method, u string, body any) (*http.Response, *http.Request, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.PreferWaitSeconds > 0 {
		req.Header.Set(aauth.HeaderPrefer, "wait="+strconv.Itoa(c.PreferWaitSeconds))
	}
	if err := c.Signer.SignRequest(req); err != nil {
		return nil, nil, err
	}
	res, err := c.client().Do(req)
	return res, req, err
}

func drain(res *http.Response) {
	// The body is discarded; a read or close error carries nothing to act on.
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

// parseResponse maps an AS response (§9.1.2): 200 with an auth token, 202
// with a same-origin Location and its requirement, or a terminal problem
// to relay. Anything else — a 402 this client does not settle, a body it
// cannot read — is an error, which the PS answers as_unreachable.
func parseResponse(reqURL *url.URL, res *http.Response) (*personserver.FederationResponse, error) {
	defer drain(res)
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		var tr aauth.AuthTokenResponse
		if err := json.Unmarshal(body, &tr); err != nil || tr.AuthToken == "" {
			return nil, fmt.Errorf("accessserver: malformed token response: %s", body)
		}
		return &personserver.FederationResponse{AuthToken: tr.AuthToken, ExpiresIn: tr.ExpiresIn}, nil
	case http.StatusAccepted:
		return parsePending(reqURL, res, body)
	case http.StatusPaymentRequired:
		return nil, errors.New("accessserver: the access server requires payment, which this client does not settle")
	}
	var pb struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &pb) != nil || pb.Error == "" {
		return nil, fmt.Errorf("accessserver: status %d: %s", res.StatusCode, body)
	}
	if res.StatusCode >= 500 && pb.Error == aauth.TokenErrServerError {
		return nil, fmt.Errorf("accessserver: %s: %s", pb.Error, pb.Detail)
	}
	return &personserver.FederationResponse{ErrorStatus: res.StatusCode, ErrorCode: pb.Error, ErrorDetail: pb.Detail}, nil
}

func parsePending(reqURL *url.URL, res *http.Response, body []byte) (*personserver.FederationResponse, error) {
	loc := res.Header.Get(aauth.HeaderLocation)
	if loc == "" {
		return nil, errors.New("accessserver: 202 without Location")
	}
	u, err := reqURL.Parse(loc)
	if err != nil {
		return nil, err
	}
	if u.Scheme != reqURL.Scheme || u.Host != reqURL.Host {
		return nil, fmt.Errorf("accessserver: 202 Location %q is not same-origin", u)
	}
	out := &personserver.FederationResponse{PendingURL: u.String()}
	if ra, err := strconv.Atoi(res.Header.Get(aauth.HeaderRetryAfter)); err == nil && ra > 0 {
		out.RetryAfter = ra
	}
	if h := res.Header.Get(aauth.HeaderRequirement); h != "" {
		if out.Requirement, err = aauth.ParseRequirement(h); err != nil {
			return nil, err
		}
	}
	var pb struct {
		Status         string   `json:"status"`
		Clarification  string   `json:"clarification"`
		Options        []string `json:"options"`
		Timeout        int      `json:"timeout"`
		RequiredClaims []string `json:"required_claims"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &pb); err != nil {
			return nil, fmt.Errorf("accessserver: malformed pending body: %w", err)
		}
	}
	out.Status, out.RequiredClaims = pb.Status, pb.RequiredClaims
	if pb.Clarification != "" {
		out.Question = &personserver.Question{Text: pb.Clarification, Options: pb.Options, Timeout: pb.Timeout}
	}
	return out, nil
}
