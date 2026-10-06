package aauth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Transport is a protocol-aware http.RoundTripper for agents. Wrap any HTTP
// client with it and AAuth disappears from application code:
//
//	hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
//	res, err := hc.Get("https://files.example/files")   // just works
//
// Per request it:
//
//   - signs with the agent's key, presenting the freshest credential for the
//     target origin (auth token if one is cached, else the agent token) and
//     any cached AAuth-Access opaque token (§6.4) bound into the signature;
//   - on 401 requirement=agent-token (§6.3), retries with the agent token;
//   - on 401 requirement=auth-token (§6.6), verifies the resource-token
//     challenge (§6.7.3), exchanges it at the PS token endpoint — following
//     deferred (202) waits — caches the auth token, and retries. Step-up
//     re-challenges (§6.6) trigger a fresh exchange;
//   - follows resource-managed 202 interaction waits (§6.5), surfacing
//     requirement=interaction via OnRequirement;
//   - honors AAuth-Access rolling refresh: a new header value on any
//     response replaces the cached token (§6.4).
//
// Request bodies are buffered in memory so retries can re-sign and resend;
// bound with MaxBodyBytes.
type Transport struct {
	// Agent is the identity every request is signed as. Required.
	Agent *Agent
	// PS performs token exchanges. Optional: without it, auth-token
	// challenges fail with the challenge error (identity-only deployments).
	PS *PSClient
	// Base is the underlying RoundTripper (default http.DefaultTransport).
	Base http.RoundTripper
	// OnRequirement surfaces interaction requirements (URL + code) that
	// arrive while a request is deferred.
	OnRequirement func(Requirement)
	// MaxBodyBytes bounds request-body buffering (default 4 MiB).
	MaxBodyBytes int64
	// ExpiryLeeway is subtracted from auth-token lifetimes when caching
	// (default 60s), so tokens are refreshed before servers reject them.
	ExpiryLeeway time.Duration

	mu     sync.Mutex
	auth   map[string]cachedAuth // origin → auth token
	access map[string]string     // origin → AAuth-Access opaque token
}

type cachedAuth struct {
	token   string
	expires time.Time
}

// NewTransport builds a Transport for agent, exchanging tokens at ps
// (ps may be nil for identity-only use).
func NewTransport(agent *Agent, ps *PSClient) *Transport {
	return &Transport{Agent: agent, PS: ps}
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func origin(req *http.Request) string {
	return req.URL.Scheme + "://" + req.URL.Host
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Agent == nil {
		return nil, fmt.Errorf("aauth: Transport.Agent is required")
	}
	body, err := t.bufferBody(req)
	if err != nil {
		return nil, err
	}
	org := origin(req)

	// First attempt with the best cached credential.
	res, err := t.send(req, body, t.credential(org), t.cachedAccess(org))
	if err != nil {
		return nil, err
	}
	res, err = t.followDeferred(req, res)
	if err != nil {
		return nil, err
	}
	t.observeAccess(org, res)
	if res.StatusCode != http.StatusUnauthorized {
		return res, nil
	}
	reqmt, perr := ParseRequirement(res.Header.Get(HeaderRequirement))
	if perr != nil {
		return res, nil // plain 401, not an AAuth challenge — caller's problem
	}
	drainBody(res.Body)

	var cred string
	switch reqmt.Requirement {
	case RequirementAgentToken:
		// §6.3: the resource wants our agent token specifically.
		cred, err = t.Agent.MintToken()
		if err != nil {
			return nil, err
		}
	case RequirementAuthToken:
		// §6.6: verify the challenge, exchange at the PS, cache, retry.
		if t.PS == nil {
			return nil, fmt.Errorf("aauth: resource at %s requires an auth token but Transport.PS is not configured", org)
		}
		if _, err := VerifyResourceChallenge(reqmt.ResourceToken, org, t.Agent); err != nil {
			return nil, fmt.Errorf("aauth: challenge from %s: %w", org, err)
		}
		grant, err := t.PS.ExchangeToken(req.Context(), TokenRequest{ResourceToken: reqmt.ResourceToken})
		if err != nil {
			return nil, err
		}
		t.storeAuth(org, grant)
		cred = grant.AuthToken
	default:
		return nil, fmt.Errorf("aauth: unsupported requirement %q from %s", reqmt.Requirement, org)
	}

	res2, err := t.send(req, body, cred, t.cachedAccess(org))
	if err != nil {
		return nil, err
	}
	res2, err = t.followDeferred(req, res2)
	if err != nil {
		return nil, err
	}
	t.observeAccess(org, res2)
	return res2, nil
}

// send clones req, attaches credential + optional AAuth-Access, signs, sends.
func (t *Transport) send(req *http.Request, body []byte, credential, access string) (*http.Response, error) {
	c := req.Clone(req.Context())
	if body != nil {
		c.Body = io.NopCloser(bytes.NewReader(body))
		c.ContentLength = int64(len(body))
	}
	// A clean signature set per attempt.
	c.Header.Del(HeaderSignature)
	c.Header.Del(HeaderSignatureInput)
	c.Header.Del("Content-Digest")
	if credential == "" {
		tok, err := t.Agent.MintToken()
		if err != nil {
			return nil, err
		}
		credential = tok
	}
	AttachSignatureKey(c, credential)
	if access != "" {
		c.Header.Set("Authorization", "AAuth "+access)
	}
	if err := SignRequest(c, t.Agent.Key, t.Agent.Thumbprint()); err != nil {
		return nil, err
	}
	return t.base().RoundTrip(c)
}

// followDeferred drives resource-managed 202 waits (§6.5) with signed polls.
func (t *Transport) followDeferred(req *http.Request, res *http.Response) (*http.Response, error) {
	if res.StatusCode != http.StatusAccepted {
		return res, nil
	}
	return FollowDeferred(req.Context(), &http.Client{Transport: t.base()}, req.URL, res, DeferredOptions{
		OnRequirement: t.OnRequirement,
		Sign: func(poll *http.Request) error {
			tok, err := t.Agent.MintToken()
			if err != nil {
				return err
			}
			AttachSignatureKey(poll, tok)
			return SignRequest(poll, t.Agent.Key, t.Agent.Thumbprint())
		},
	})
}

func (t *Transport) bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	max := t.MaxBodyBytes
	if max <= 0 {
		max = 4 << 20
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, max+1))
	closeBody(req.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("aauth: request body exceeds Transport.MaxBodyBytes (%d)", max)
	}
	return b, nil
}

func (t *Transport) credential(origin string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ca, ok := t.auth[origin]; ok && time.Now().Before(ca.expires) {
		return ca.token
	}
	return ""
}

func (t *Transport) storeAuth(origin string, grant *TokenResponse) {
	leeway := t.ExpiryLeeway
	if leeway <= 0 {
		leeway = time.Minute
	}
	ttl := time.Duration(grant.ExpiresIn)*time.Second - leeway
	if ttl <= 0 {
		return // too short to cache; next request re-exchanges
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.auth == nil {
		t.auth = map[string]cachedAuth{}
	}
	t.auth[origin] = cachedAuth{token: grant.AuthToken, expires: time.Now().Add(ttl)}
}

func (t *Transport) cachedAccess(origin string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.access[origin]
}

// observeAccess implements AAuth-Access rolling refresh (§6.4).
func (t *Transport) observeAccess(origin string, res *http.Response) {
	vals := res.Header.Values("AAuth-Access")
	if len(vals) != 1 {
		return // absent, or multiple credentials (MUST reject) — ignore
	}
	v := strings.TrimSpace(vals[0])
	if v == "" || strings.ContainsAny(v, " \t") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return // not a token68 — reject per §6.4
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.access == nil {
		t.access = map[string]string{}
	}
	t.access[origin] = v
}
