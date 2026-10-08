package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ServerMetadata holds the members defined identically across all four
// metadata documents (draft -11 §11.2, Table 12). It is embedded in each
// role's document type, so its members appear at the top level of the JSON
// object. A reader ignores members it does not recognize.
type ServerMetadata struct {
	// Issuer is the server's HTTPS URL (REQUIRED). It MUST equal the URL
	// the document was fetched from minus /.well-known/{dwk}
	// ([FetchMetadata] checks this) and is the iss of the JWTs the server
	// issues.
	Issuer string `json:"issuer"`
	// JWKSURI is the URL of the server's JSON Web Key Set. REQUIRED for an
	// agent provider, PS, and AS; for a resource only when it issues
	// resource tokens or makes signed calls (§11.2.4).
	JWKSURI string `json:"jwks_uri,omitempty"`
	// AcceptSignatureAlgs lists the fully-specified JWS algorithms the
	// server's verifier accepts, exactly the set, with the semantics of the
	// Accept-Signature-Alg response header. One list per server.
	AcceptSignatureAlgs []string `json:"accept_signature_algs,omitempty"`
	// Name is a human-readable display name.
	Name string `json:"name,omitempty"`
	// Description is Markdown describing the server, for consent screens
	// and dashboards. Implementations MUST sanitize it before rendering.
	Description string `json:"description,omitempty"`
	// LogoURI, LogoDarkURI, DocumentationURI, TOSURI, and PolicyURI are
	// https URLs for the server's logo (and dark-background variant),
	// developer documentation, terms of service, and privacy policy.
	LogoURI          string `json:"logo_uri,omitempty"`
	LogoDarkURI      string `json:"logo_dark_uri,omitempty"`
	DocumentationURI string `json:"documentation_uri,omitempty"`
	TOSURI           string `json:"tos_uri,omitempty"`
	PolicyURI        string `json:"policy_uri,omitempty"`
}

// requireMembers fails with [ErrMetadataIncomplete] naming the first empty
// value among the (name, value) pairs.
func requireMembers(doc string, pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			return fmt.Errorf("%w: %s has no %s", ErrMetadataIncomplete, doc, pairs[i])
		}
	}
	return nil
}

// ErrMetadataIncomplete means a metadata document lacks a member its role
// REQUIRES (draft -11 §11.2).
var ErrMetadataIncomplete = errors.New("aauth: metadata document incomplete")

// AgentProviderMetadata is /.well-known/aauth-agent.json (draft -11
// §11.2.1) — published by an agent provider, or by a self-hosted agent
// acting as its own provider, so verifiers can discover the token-signing
// JWKS.
type AgentProviderMetadata struct {
	ServerMetadata
	// CallbackEndpoint is the agent's HTTPS callback endpoint (§7.3).
	CallbackEndpoint string `json:"callback_endpoint,omitempty"`
	// EventEndpoint is where the AP receives event tokens from resources
	// (AAuth Events).
	EventEndpoint string `json:"event_endpoint,omitempty"`
	// LocalhostCallbackAllowed permits localhost callbacks. Default false.
	LocalhostCallbackAllowed bool `json:"localhost_callback_allowed,omitempty"`
}

// Validate checks the members an agent provider MUST publish: issuer and
// jwks_uri.
func (m AgentProviderMetadata) Validate() error {
	return requireMembers(WellKnownAgent, "issuer", m.Issuer, "jwks_uri", m.JWKSURI)
}

// PersonServerMetadata is /.well-known/aauth-person.json (draft -11
// §11.2.2). Its four REQUIRED members — issuer, jwks_uri,
// auth_token_endpoint, and person_token_endpoint — are the whole of what a
// conformant PS publishes; the OPTIONAL endpoints add missions, permission
// checks, audit, and the relay channel to the person.
type PersonServerMetadata struct {
	ServerMetadata
	// AuthTokenEndpoint is where agents send auth token requests (§7.2).
	// REQUIRED. Earlier drafts called it token_endpoint.
	AuthTokenEndpoint string `json:"auth_token_endpoint"`
	// PersonTokenEndpoint is where agents request a person token for a
	// resource (§7.1). REQUIRED.
	PersonTokenEndpoint string `json:"person_token_endpoint"`
	// MissionEndpoint is where an agent proposes, updates, and completes
	// the missions it owns (§8); a mission's own URL is
	// {mission_endpoint}/{mission_s256}.
	MissionEndpoint string `json:"mission_endpoint,omitempty"`
	// PermissionEndpoint is where agents request permission for actions no
	// remote resource governs (§7.7).
	PermissionEndpoint string `json:"permission_endpoint,omitempty"`
	// AuditEndpoint is where agents log actions performed (§7.8).
	AuditEndpoint string `json:"audit_endpoint,omitempty"`
	// InteractionEndpoint is where agents relay interactions to the user
	// through the PS (§7.6).
	InteractionEndpoint string `json:"interaction_endpoint,omitempty"`
	// MissionControlEndpoint is the PS's mission control plane, for parties
	// other than the owning agent (§8.6); defined by a companion
	// specification.
	MissionControlEndpoint string `json:"mission_control_endpoint,omitempty"`
	// RevocationEndpoint is where an agent provider revokes an agent token
	// it issued, and a resource a resource token this PS holds (§11.12).
	// RECOMMENDED.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// ScopesSupported lists the scope values the PS supports, including
	// identity and enterprise scopes. RECOMMENDED.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ClaimsSupported lists the identity claim names the PS can provide.
	// RECOMMENDED.
	ClaimsSupported []string `json:"claims_supported,omitempty"`
}

// Validate checks the members a PS MUST publish: issuer, jwks_uri,
// auth_token_endpoint, and person_token_endpoint.
func (m PersonServerMetadata) Validate() error {
	return requireMembers(WellKnownPerson,
		"issuer", m.Issuer, "jwks_uri", m.JWKSURI,
		"auth_token_endpoint", m.AuthTokenEndpoint, "person_token_endpoint", m.PersonTokenEndpoint)
}

// AccessServerMetadata is /.well-known/aauth-access.json (draft -11
// §11.2.3), published by a resource's Access Server.
type AccessServerMetadata struct {
	ServerMetadata
	// AuthTokenEndpoint is where PSes send token requests (§9.1).
	// REQUIRED.
	AuthTokenEndpoint string `json:"auth_token_endpoint"`
	// RevocationEndpoint is where a PS revokes a person token it presented
	// to this AS, and a resource a resource token whose aud is this AS
	// (§11.12). RECOMMENDED.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
}

// Validate checks the members an AS MUST publish: issuer, jwks_uri, and
// auth_token_endpoint.
func (m AccessServerMetadata) Validate() error {
	return requireMembers(WellKnownAccess,
		"issuer", m.Issuer, "jwks_uri", m.JWKSURI, "auth_token_endpoint", m.AuthTokenEndpoint)
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
// AccessMode* constants and [ResourceMetadata.EffectiveAccessMode]. A
// resource that publishes none can still verify identity-based access and
// issue resource tokens and interaction requirements via 401 responses.
type ResourceMetadata struct {
	ServerMetadata
	// AccessMode is the declared access mode (AccessMode*). Advisory.
	AccessMode string `json:"access_mode,omitempty"`
	// AuthorizationEndpoint is where agents request authorization ahead of
	// a challenge (§6.6).
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	// ScopeDescriptions maps scope values to Markdown for consent display
	// (§11.10).
	ScopeDescriptions map[string]string `json:"scope_descriptions,omitempty"`
	// SignatureWindow is the signature validity window in seconds for the
	// created timestamp (§11.3.4). Zero means the default, 60.
	SignatureWindow int `json:"signature_window,omitempty"`
	// AdditionalSignatureComponents are HTTP message components agents
	// MUST cover when signing requests to this resource, beyond the base
	// set (§11.3.3.1).
	AdditionalSignatureComponents []string `json:"additional_signature_components,omitempty"`
	// RevocationEndpoint is where the issuer of an auth token or person
	// token for this resource revokes it (§11.12). RECOMMENDED for a
	// resource that accepts person tokens.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
}

// Validate checks the member a resource MUST publish: issuer.
func (m ResourceMetadata) Validate() error {
	return requireMembers(WellKnownResource, "issuer", m.Issuer)
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
	hc = discoveryClient(hc)
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

// LinkRelResource is the aauth-resource link relation (draft -11 §11.2.5):
// a Link header field (or an HTML link element) naming the resource
// metadata document that governs what a response describes, for an agent
// that has reached a developer portal or API host without the resource
// identifier.
const LinkRelResource = "aauth-resource"

// resourceMetadataSuffix is the path every aauth-resource link target ends
// with.
const resourceMetadataSuffix = "/.well-known/" + WellKnownResource

// ResourceMetadataLink returns a Link header field value naming the
// metadata document of resource, a resource identifier (§11.2.5):
//
//	<https://api.example/.well-known/aauth-resource.json>; rel="aauth-resource"
func ResourceMetadataLink(resource string) string {
	return "<" + resource + resourceMetadataSuffix + `>; rel="` + LinkRelResource + `"`
}

// ResourceLinks returns the resource identifiers named by aauth-resource
// Link header fields in h (draft -11 §11.2.5), in order and without
// duplicates. A target that is not a server identifier followed by
// /.well-known/aauth-resource.json is skipped: an agent MUST NOT fetch a
// target of any other form. Fetch a returned identifier's document with
// [FetchMetadata] and WellKnownResource, which verifies that its issuer
// equals the identifier.
//
// The relation says nothing about the response that carries it: a 401
// still carries its requirement in AAuth-Requirement. Verifiers never use
// it; keys are discovered from a signer's iss and dwk (§13.6).
func ResourceLinks(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Link") {
		for _, l := range parseLinkHeader(v) {
			if !hasRel(l.rel, LinkRelResource) {
				continue
			}
			id, ok := strings.CutSuffix(l.target, resourceMetadataSuffix)
			if !ok || ValidateServerIdentifier(id) != nil || contains(out, id) {
				continue
			}
			out = append(out, id)
		}
	}
	return out
}

// link is one link-value of an RFC 8288 Link header field.
type link struct{ target, rel string }

// parseLinkHeader parses a Link header field value (RFC 8288 §3) into its
// link-values, keeping each target and rel parameter. Malformed
// link-values are skipped.
func parseLinkHeader(v string) []link {
	var out []link
	for {
		v = strings.TrimLeft(v, " \t,")
		if v == "" || v[0] != '<' {
			return out
		}
		end := strings.IndexByte(v, '>')
		if end < 0 {
			return out
		}
		l := link{target: v[1:end]}
		v = v[end+1:]
		// Parameters run to the next comma outside a quoted string.
		for {
			v = strings.TrimLeft(v, " \t")
			if v == "" || v[0] != ';' {
				break
			}
			v = strings.TrimLeft(v[1:], " \t")
			i := strings.IndexAny(v, "=;,")
			if i < 0 {
				v = ""
				break
			}
			name := strings.ToLower(strings.TrimSpace(v[:i]))
			if v[i] != '=' {
				v = v[i:]
				continue
			}
			v = strings.TrimLeft(v[i+1:], " \t")
			var val string
			if strings.HasPrefix(v, `"`) {
				var b strings.Builder
				j := 1
				for ; j < len(v) && v[j] != '"'; j++ {
					if v[j] == '\\' && j+1 < len(v) {
						j++
					}
					b.WriteByte(v[j])
				}
				val = b.String()
				if j < len(v) {
					j++
				}
				v = v[j:]
			} else {
				j := strings.IndexAny(v, ";,")
				if j < 0 {
					j = len(v)
				}
				val, v = strings.TrimSpace(v[:j]), v[j:]
			}
			if name == "rel" && l.rel == "" {
				l.rel = val // only the first rel parameter counts (RFC 8288 §3.3)
			}
		}
		out = append(out, l)
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[i+1:]
		} else {
			return out
		}
	}
}

// hasRel reports whether the space-separated relation types in rel include
// want, compared case-insensitively (RFC 8288 §2.1.1).
func hasRel(rel, want string) bool {
	for _, r := range strings.Fields(rel) {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}
