package agentprovider

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// Client is the agent side of a hosted agent provider: it obtains agent
// tokens from a [Server]'s endpoints. Pair it with [aauth.WithTokenSource]
// so an [aauth.Agent] presents provider-issued tokens:
//
//	ap := &agentprovider.Client{BaseURL: "https://ap.example"}
//	src := ap.TokenSource(func(ctx context.Context) (*agentprovider.TokenResponse, error) {
//		return ap.Issue(ctx, key, nil)
//	})
//	agent, _ := aauth.NewAgent(id, aauth.WithKey(key), aauth.WithTokenSource(src))
type Client struct {
	// BaseURL is the provider's issuer.
	BaseURL string
	// Paths are the provider's endpoint paths (default DefaultPaths).
	Paths Paths
	// HTTPClient makes requests; nil uses http.DefaultClient.
	HTTPClient *http.Client
}

func (c *Client) path(p, def string) string {
	if p == "" {
		p = def
	}
	return strings.TrimSuffix(c.BaseURL, "/") + p
}

// Issue requests an agent token for key, proving possession by signing
// the request with it under the hwk scheme (enrollment, or single-key
// refresh; bootstrap §8.2). body carries the provider's own enrollment
// fields, and attestation evidence in "attestation"; nil sends {}.
func (c *Client) Issue(ctx context.Context, key crypto.Signer, body any) (*TokenResponse, error) {
	req, err := c.newRequest(ctx, c.path(c.Paths.Token, DefaultPaths().Token), body)
	if err != nil {
		return nil, err
	}
	if err := SignHWK(req, key); err != nil {
		return nil, err
	}
	return c.do(req)
}

// Refresh performs the two-key refresh (bootstrap §8.1): durable — the
// enrolled, typically hardware-bound key — names ephemeral in a jkt-jwt,
// and ephemeral signs the request. The new token binds ephemeral.
func (c *Client) Refresh(ctx context.Context, durable, ephemeral crypto.Signer, body any) (*TokenResponse, error) {
	naming, err := NewNamingJWT(durable, ephemeral.Public(), 5*time.Minute)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, c.path(c.Paths.Refresh, DefaultPaths().Refresh), body)
	if err != nil {
		return nil, err
	}
	if err := SignJKTJWT(req, naming, ephemeral); err != nil {
		return nil, err
	}
	return c.do(req)
}

// Subagent requests a sub-agent token for the key subPub from the
// provider, signed by parent with its own agent token (bootstrap §9.2).
// discriminator may be empty to let the provider choose.
func (c *Client) Subagent(ctx context.Context, parent *aauth.Agent, subPub crypto.PublicKey, discriminator string) (*TokenResponse, error) {
	j, err := aauth.NewJWK(subPub)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, c.path(c.Paths.Subagent, DefaultPaths().Subagent), subagentBody{JWK: &j, Discriminator: discriminator})
	if err != nil {
		return nil, err
	}
	tok, err := parent.MintToken()
	if err != nil {
		return nil, err
	}
	aauth.AttachSignatureKey(req, tok)
	if err := aauth.SignRequest(req, parent.Key, ""); err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) newRequest(ctx context.Context, u string, body any) (*http.Request, error) {
	if body == nil {
		body = struct{}{}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request) (*TokenResponse, error) {
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		// The body has been read or is being discarded; a close error is
		// not actionable.
		_ = res.Body.Close()
	}()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentprovider: status %d: %s", res.StatusCode, b)
	}
	var tr TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil || tr.AgentToken == "" {
		return nil, fmt.Errorf("agentprovider: malformed token response: %s", b)
	}
	return &tr, nil
}

// TokenSource caches the token fetch returns and fetches a new one when
// fewer than the refresh margin (aauth.DefaultRefreshMargin) remain, for
// use with [aauth.WithTokenSource].
func (c *Client) TokenSource(fetch func(ctx context.Context) (*TokenResponse, error)) func() (string, error) {
	var (
		mu  sync.Mutex
		tok string
		exp time.Time
	)
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if tok != "" && time.Now().Add(aauth.DefaultRefreshMargin).Before(exp) {
			return tok, nil
		}
		tr, err := fetch(context.Background())
		if err != nil {
			return "", err
		}
		tok, exp = tr.AgentToken, time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second)
		return tok, nil
	}
}
