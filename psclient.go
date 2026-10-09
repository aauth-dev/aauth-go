package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// PSClient calls a Person Server on behalf of an agent (draft -11 §7).
// Every PS endpoint authenticates the agent by an HTTP message signature
// with its agent token in Signature-Key (§11.3).
//
// Endpoint URLs come from the PS's metadata (§11.2.2) after [PSClient.Discover],
// or are set directly; when neither, each defaults to a path under BaseURL.
type PSClient struct {
	// BaseURL of the PS, e.g. "https://ps.example". It is the PS's issuer
	// when Discover has not replaced it.
	BaseURL string
	// AuthTokenEndpoint is the auth token endpoint (§7.2); default
	// BaseURL+"/token". Earlier drafts called it the token endpoint.
	AuthTokenEndpoint string
	// PersonTokenEndpoint is the person token endpoint (§7.1); default
	// BaseURL+"/person".
	PersonTokenEndpoint string
	// PermissionEndpoint is the permission endpoint (§7.7); default
	// BaseURL+"/permission".
	PermissionEndpoint string
	// AuditEndpoint is the audit endpoint (§7.8); default BaseURL+"/audit".
	AuditEndpoint string
	// InteractionEndpoint is the interaction endpoint (§7.6); default
	// BaseURL+"/interaction".
	InteractionEndpoint string
	// MissionEndpoint is the mission endpoint (§8); default
	// BaseURL+"/mission".
	MissionEndpoint string
	// Agent is the identity this client acts as. Required.
	Agent *Agent
	// HTTPClient makes requests; nil uses [EgressClient], which reaches only
	// public https destinations. The PS may be named by an upstream token
	// and advertises its own endpoints, so a client that reaches internal
	// addresses is an explicit opt-in: set HTTPClient (for example to
	// http.DefaultClient in local development).
	HTTPClient *http.Client
	// PreferWaitSeconds sets `Prefer: wait=N` on requests that may defer.
	PreferWaitSeconds int
	// OnRequirement is invoked when a deferred (202) response carries an
	// AAuth-Requirement — e.g. requirement=interaction with the URL and code
	// the user must visit. The agent surfaces it; polling continues.
	OnRequirement func(Requirement)
	// OnClarification answers a requirement=clarification 202 (§7.5) that
	// arrives during a deferred request. Nil leaves clarifications
	// unanswered (the request eventually times out server-side).
	OnClarification func(Clarification) (ClarificationReply, error)
	// RefreshMargin is how long before its exp a cached token is replaced
	// rather than presented (draft -11 §7.9.1); zero means
	// DefaultRefreshMargin.
	RefreshMargin time.Duration

	// metadata is the discovered document, when Discover has run.
	metadata *PersonServerMetadata

	mu      sync.Mutex
	persons map[personCacheKey]cachedToken // person token cache (§7.1)
}

// NewPSClient returns a client with sane defaults. Its HTTPClient is nil,
// so requests go through [EgressClient]; see [PSClient.HTTPClient].
func NewPSClient(baseURL string, agent *Agent) *PSClient {
	return &PSClient{BaseURL: baseURL, Agent: agent, PreferWaitSeconds: 45}
}

// httpClient returns HTTPClient, or the guarded default.
func (c *PSClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return defaultEgressClient
}

// Discover fetches the PS's metadata from {BaseURL}/.well-known/aauth-person.json
// (draft -11 §11.2.2), verifies its issuer and REQUIRED members, and fills
// every endpoint not already set.
func (c *PSClient) Discover(ctx context.Context) (*PersonServerMetadata, error) {
	var md PersonServerMetadata
	if err := FetchMetadata(ctx, c.httpClient(), c.BaseURL, WellKnownPerson, &md); err != nil {
		return nil, err
	}
	if err := md.Validate(); err != nil {
		return nil, err
	}
	for _, e := range []struct {
		dst *string
		v   string
	}{
		{&c.AuthTokenEndpoint, md.AuthTokenEndpoint},
		{&c.PersonTokenEndpoint, md.PersonTokenEndpoint},
		{&c.PermissionEndpoint, md.PermissionEndpoint},
		{&c.AuditEndpoint, md.AuditEndpoint},
		{&c.InteractionEndpoint, md.InteractionEndpoint},
		{&c.MissionEndpoint, md.MissionEndpoint},
	} {
		if *e.dst == "" {
			*e.dst = e.v
		}
	}
	c.metadata = &md
	return &md, nil
}

// Metadata returns the document Discover fetched, or nil.
func (c *PSClient) Metadata() *PersonServerMetadata { return c.metadata }

// Issuer is the PS's identifier: the discovered issuer, else BaseURL. It
// is the iss of the person tokens and the ps of the resource and auth
// tokens this PS is named in.
func (c *PSClient) Issuer() string {
	if c.metadata != nil {
		return c.metadata.Issuer
	}
	return c.BaseURL
}

// endpoint returns set when non-empty, else BaseURL+path.
func (c *PSClient) endpoint(set, path string) string {
	if set != "" {
		return set
	}
	return c.BaseURL + path
}

// requireAgent fails when the client has no agent.
func (c *PSClient) requireAgent() error {
	if c.Agent == nil {
		return fmt.Errorf("aauth: PSClient.Agent is required")
	}
	return nil
}

// deferredOptions builds the DeferredOptions shared by the client's flows,
// signing each poll/answer with the agent's own token.
func (c *PSClient) deferredOptions() DeferredOptions {
	return DeferredOptions{
		PreferWaitSeconds: c.PreferWaitSeconds,
		OnRequirement:     c.OnRequirement,
		OnClarification:   c.OnClarification,
		Sign:              c.signAsAgent,
	}
}

// signAsAgent attaches a fresh agent token and signs req.
func (c *PSClient) signAsAgent(req *http.Request) error {
	tok, err := c.Agent.MintToken()
	if err != nil {
		return fmt.Errorf("aauth: mint agent token: %w", err)
	}
	AttachSignatureKey(req, tok)
	return SignRequest(req, c.Agent.Key, "")
}

// post makes a signed JSON POST to endpoint as the agent (draft -11 §7:
// HTTP Sig with the agent token in Signature-Key, covering content-digest
// and content-type) and, when follow is set, follows deferred (202)
// responses to a terminal one (§11.8). The caller closes the body.
func (c *PSClient) post(ctx context.Context, endpoint string, payload any, follow bool) (*http.Response, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if follow && c.PreferWaitSeconds > 0 {
		req.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", c.PreferWaitSeconds))
	}
	if err := c.signAsAgent(req); err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}
	if follow {
		return DoDeferred(ctx, c.httpClient(), req, c.deferredOptions())
	}
	return c.httpClient().Do(req)
}

// readErrorBody reads a bounded prefix of a non-success response body for
// error reporting.
func readErrorBody(res *http.Response) []byte {
	b, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return fmt.Appendf(b, " (reading body: %v)", err)
	}
	return b
}
