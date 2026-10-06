package aauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AgentProviderMetadata is /.well-known/aauth-agent.json — published by an
// agent provider (or by a self-hosted agent acting as its own provider) so
// verifiers can discover the token-signing JWKS.
type AgentProviderMetadata struct {
	Issuer  string `json:"issuer,omitempty"` // the provider's issuer URL
	JWKSURI string `json:"jwks_uri"`         // URL of the token-signing JWKS
}

// PersonServerMetadata is /.well-known/aauth-person.json.
type PersonServerMetadata struct {
	Issuer              string `json:"issuer,omitempty"`               // the PS issuer URL
	JWKSURI             string `json:"jwks_uri,omitempty"`             // URL of the PS signing JWKS
	TokenEndpoint       string `json:"token_endpoint,omitempty"`       // where agents exchange resource tokens
	PermissionEndpoint  string `json:"permission_endpoint,omitempty"`  // where agents request permission
	AuditEndpoint       string `json:"audit_endpoint,omitempty"`       // where agents log actions
	MissionEndpoint     string `json:"mission_endpoint,omitempty"`     // where agents propose missions
	InteractionEndpoint string `json:"interaction_endpoint,omitempty"` // where the user completes interactions
}

// Access mode values for ResourceMetadata.AccessMode (draft -11 §11.2.4;
// AAuth Access Mode Value registry, §15.11): the credential flow a resource
// expects, so an agent can plan its first call. The declaration is
// advisory: a resource MAY return any AAuth-Requirement at runtime and MAY
// apply different modes to different endpoints.
const (
	// AccessModeAgentToken: the agent signs with its agent token; the
	// resource authorizes on the agent's identity alone. The default.
	AccessModeAgentToken = "agent-token"
	// AccessModePersonToken: the agent signs with a person token; the
	// resource authorizes on the person's identity alone (§4.2.3).
	AccessModePersonToken = "person-token"
	// AccessModeSessionToken: the agent completes the resource's own
	// interaction flow and receives a session token via AAuth-Access
	// (§6.2, §6.3). Earlier drafts called this mode aauth-access-token.
	AccessModeSessionToken = "session-token"
	// AccessModeAuthToken: the agent obtains an auth token from its PS
	// using a resource token; the initial call MUST present a person
	// token (§4.2.4, §4.2.5).
	AccessModeAuthToken = "auth-token"
)

// ResourceMetadata is /.well-known/aauth-resource.json (draft -11 §11.2.4).
// AccessMode declares the credential flow the resource expects; see the
// AccessMode* constants and [ResourceMetadata.EffectiveAccessMode].
type ResourceMetadata struct {
	Issuer                        string   `json:"issuer,omitempty"`                          // the resource issuer URL
	JWKSURI                       string   `json:"jwks_uri,omitempty"`                        // URL of the resource signing JWKS
	AuthorizationEndpoint         string   `json:"authorization_endpoint,omitempty"`          // where agents proactively request access
	AccessMode                    string   `json:"access_mode,omitempty"`                     // declared access mode (AccessMode*)
	AdditionalSignatureComponents []string `json:"additional_signature_components,omitempty"` // extra components the resource requires signed
}

// EffectiveAccessMode returns the declared access mode an agent plans
// with: AccessMode when it is a value this implementation recognizes, else
// AccessModeAgentToken — the default when none is declared, and how an
// agent proceeds when it does not recognize the value (§11.2.4).
func (m ResourceMetadata) EffectiveAccessMode() string {
	switch m.AccessMode {
	case AccessModePersonToken, AccessModeSessionToken, AccessModeAuthToken:
		return m.AccessMode
	}
	return AccessModeAgentToken
}

// FetchMetadata GETs {base}/.well-known/{doc} and decodes it into dst,
// first verifying the document's issuer (draft -11 §11.2; signature-key
// §3.6): the issuer member MUST be present ([ErrIssuerMissing]) and MUST
// equal base by byte equality ([ErrIssuerMismatch]). This prevents a
// document hosted at one domain from claiming the issuer of another.
func FetchMetadata(ctx context.Context, hc *http.Client, base, doc string, dst any) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	u := strings.TrimSuffix(base, "/") + "/.well-known/" + doc
	body, _, err := fetchJSON(ctx, hc, u)
	if err != nil {
		return fmt.Errorf("aauth: metadata: %w", err)
	}
	var head struct {
		Issuer *string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return fmt.Errorf("aauth: metadata %s: %w", u, err)
	}
	switch {
	case head.Issuer == nil || *head.Issuer == "":
		return fmt.Errorf("%w: %s", ErrIssuerMissing, u)
	case *head.Issuer != base:
		return fmt.Errorf("%w: document at %s claims issuer %q", ErrIssuerMismatch, u, *head.Issuer)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("aauth: metadata %s: %w", u, err)
	}
	return nil
}

// maxDocumentBytes bounds metadata and JWKS response bodies.
const maxDocumentBytes = 1 << 20

// fetchJSON GETs u and returns the body (bounded by maxDocumentBytes) and
// response headers. Non-200 statuses are errors.
func fetchJSON(ctx context.Context, hc *http.Client, u string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET %s: status %d", u, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxDocumentBytes {
		return nil, nil, fmt.Errorf("GET %s: response exceeds %d bytes", u, maxDocumentBytes)
	}
	return body, res.Header, nil
}
