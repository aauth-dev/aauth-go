package aauth

import (
	"context"
	"crypto"
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

// ResourceMetadata is /.well-known/aauth-resource.json. AccessMode declares
// how the resource authorizes agents (identity, resource, ps, federated).
type ResourceMetadata struct {
	Issuer                        string   `json:"issuer,omitempty"`                          // the resource issuer URL
	JWKSURI                       string   `json:"jwks_uri,omitempty"`                        // URL of the resource signing JWKS
	AuthorizationEndpoint         string   `json:"authorization_endpoint,omitempty"`          // where agents proactively request access
	AccessMode                    string   `json:"access_mode,omitempty"`                     // declared access mode
	AdditionalSignatureComponents []string `json:"additional_signature_components,omitempty"` // extra components the resource requires signed
}

// FetchMetadata GETs {base}/.well-known/{doc} and decodes into dst.
func FetchMetadata(ctx context.Context, hc *http.Client, base, doc string, dst any) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	u := strings.TrimSuffix(base, "/") + "/.well-known/" + doc
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("aauth: metadata %s: status %d", u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(dst)
}

// JWKSResolver verifies token signatures via the signature-key draft §3.6
// discovery chain: {iss}/.well-known/{dwk} → jwks_uri → key by kid.
type JWKSResolver struct {
	HTTPClient *http.Client // client for discovery fetches; nil uses http.DefaultClient
}

// ResolveKey implements KeyResolver.
func (r JWKSResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, _ *JWK) (crypto.PublicKey, error) {
	k, err := r.resolve(ctx, iss, dwk, kid)
	if err != nil {
		return nil, err
	}
	return k.PublicKey()
}

// resolve walks the discovery chain and returns the matching JWK.
func (r JWKSResolver) resolve(ctx context.Context, iss, dwk, kid string) (JWK, error) {
	if iss == "" || dwk == "" {
		return JWK{}, fmt.Errorf("%w: iss/dwk required for JWKS discovery", ErrMissingClaim)
	}
	var md AgentProviderMetadata
	if err := FetchMetadata(ctx, r.HTTPClient, iss, dwk, &md); err != nil {
		return JWK{}, err
	}
	if md.JWKSURI == "" {
		return JWK{}, fmt.Errorf("aauth: metadata at %s has no jwks_uri", iss)
	}
	hc := r.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, md.JWKSURI, nil)
	if err != nil {
		return JWK{}, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return JWK{}, err
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return JWK{}, fmt.Errorf("aauth: jwks %s: status %d", md.JWKSURI, res.StatusCode)
	}
	var set JWKS
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return JWK{}, err
	}
	for _, k := range set.Keys {
		if k.Kid == kid || kid == "" {
			return k, nil
		}
	}
	return JWK{}, fmt.Errorf("%w: no key %q in JWKS of %s", ErrUnknownKey, kid, iss)
}
