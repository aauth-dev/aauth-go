package aauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
//     target resource (its origin): a cached auth token, else — once the
//     resource has asked for the person — a person token from the PS, else
//     the agent token; and any cached session token (AAuth-Access, §6.3)
//     bound into the signature;
//   - on 401 requirement=agent-token (§6.1), retries with the agent token;
//   - on 401 requirement=person-token (§6.4), obtains a person token for the
//     resource from the PS ([PSClient.PersonToken], §7.1) and retries;
//   - on requirement=auth-token (§6.5) — a 401, or a 202 deferred delivery
//     holding the invocation (§6.5.1) — verifies the resource-token
//     challenge against the token it presented (§6.7.3), redeems it at the
//     PS auth token endpoint with that token as presented_token (§7.2),
//     checks the auth token it receives (§9.4.4), caches it, and retries
//     (401) or presents it on the polls of the pending URL (202). Step-up
//     re-challenges trigger a fresh request;
//   - follows resource-managed 202 interaction and approval waits (§6.2,
//     §11.6.4), surfacing the requirement via OnRequirement;
//   - honors session token rolling refresh: a new AAuth-Access value on any
//     response replaces the cached session token (§6.3);
//   - refreshes top-down within the refresh margin (§7.9.1): a token with
//     fewer than the margin left is not presented again — the agent token
//     is minted fresh for each request, a person token is replaced through
//     the PS cache, and an auth token is replaced by presenting the (fresh)
//     person token and redeeming the new challenge;
//   - on 401 Signature-Error clock_skew, waits out the skew the response
//     Date header shows (up to MaxClockSkewWait) and presents the same
//     signed request once more (signature-key §5.4.14);
//   - on 401 expired_jwt or revoked_jwt for a cached person or auth token,
//     drops it and falls back to the next credential (§11.12.5).
//
// A sub-agent's Transport has the sub-agent as Agent and its parent's
// [PSClient] as PS (§10.2.3): the sub-agent signs its own requests to
// resources with its own key, while the parent signs the PS requests and
// the transport adds the sub-agent's token as subagent_token, so the
// person and auth tokens bind the sub-agent's key.
//
// Request bodies are buffered in memory so retries can re-sign and resend;
// bound with MaxBodyBytes.
type Transport struct {
	// Agent is the identity every request is signed as. Required.
	Agent *Agent
	// PS obtains person tokens and auth tokens. Optional: without it,
	// person-token and auth-token requirements fail with an error
	// (identity-only deployments; an agent with no PS surfaces the
	// requirement as an error, §6.4).
	PS *PSClient
	// MissionS256, when set, is the mission person tokens are requested
	// under (§7.1, §8); it flows into resource tokens and auth tokens. It
	// is not sent with UpstreamToken, which carries the mission itself.
	MissionS256 string
	// UpstreamToken, for an intermediary in call chaining (§10.1.1), is the
	// person or auth token the calling agent presented to it. It is sent
	// as upstream_token in the person and auth token requests to PS — the
	// person server the upstream token names — so the tokens are issued
	// for that person. UpstreamExpiresAt is its exp: no downstream token
	// outlives it, and once it passes the intermediary needs a later token
	// from the calling agent. See [ChainRouter.Transport].
	UpstreamToken     string
	UpstreamExpiresAt time.Time
	// Base is the underlying RoundTripper (default http.DefaultTransport).
	Base http.RoundTripper
	// ResourceVerify verifies the signature of resource tokens in
	// auth-token challenges (§6.7.3). A nil Resolver uses a
	// [JWKSResolver], which discovers the resource's key at
	// {iss}/.well-known/aauth-resource.json.
	ResourceVerify TokenVerifyOptions
	// AuthVerify, when its Resolver is set, also verifies the signature of
	// auth tokens the PS returns (§9.4.4 step 1, SHOULD). A nil Resolver
	// runs the claim checks only: the agent trusts its PS.
	AuthVerify TokenVerifyOptions
	// OnRequirement surfaces interaction requirements (URL + code) that
	// arrive while a request is deferred.
	OnRequirement func(Requirement)
	// MaxBodyBytes bounds request-body buffering (default 4 MiB).
	MaxBodyBytes int64
	// RefreshMargin is how long before its exp a cached auth token is
	// replaced rather than presented (default DefaultRefreshMargin, five
	// minutes, §7.9.1). Person tokens follow PS.RefreshMargin.
	RefreshMargin time.Duration
	// MaxClockSkewWait bounds the wait before re-presenting a request a
	// resource refused with clock_skew (default 10 seconds). A negative
	// value disables the retry.
	MaxClockSkewWait time.Duration

	mu      sync.Mutex
	auth    map[string]cachedToken // resource → auth token
	persons map[string]bool        // resources that asked for the person (§6.4)
	session map[string]string      // resource → session token (AAuth-Access, §6.3)
}

// NewTransport builds a Transport for agent, obtaining tokens from ps
// (ps may be nil for identity-only use).
func NewTransport(agent *Agent, ps *PSClient) *Transport {
	return &Transport{Agent: agent, PS: ps}
}

// maxChallenges bounds the requirement responses one request follows:
// agent token → person token → auth token, plus a step-up.
const maxChallenges = 4

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
		return nil, errors.New("aauth: Transport.Agent is required")
	}
	ctx := req.Context()
	body, err := t.bufferBody(req)
	if err != nil {
		return nil, err
	}
	resource := origin(req)
	cred, err := t.credential(ctx, resource)
	if err != nil {
		return nil, err
	}
	skewRetried := false
	for range maxChallenges + 1 {
		signed, presented, err := t.sign(req, body, cred, t.cachedSession(resource))
		if err != nil {
			return nil, err
		}
		res, err := t.base().RoundTrip(signed)
		if err != nil {
			return nil, err
		}
		if !skewRetried && res.StatusCode == http.StatusUnauthorized {
			if wait, ok := t.clockSkewWait(res, signed, presented); ok {
				// signature-key §5.4.14: a fresh signature carries the
				// same skew; wait it out and present the same one again.
				skewRetried = true
				drainBody(res.Body)
				if err := sleepCtx(ctx, wait); err != nil {
					return nil, err
				}
				if res, err = t.base().RoundTrip(resend(signed, body)); err != nil {
					return nil, err
				}
			}
		}
		if res, err = t.followDeferred(req, res, resource, presented); err != nil {
			return nil, err
		}
		t.observeSession(resource, res)
		if res.StatusCode != http.StatusUnauthorized {
			return res, nil
		}
		// A refused cached token is dropped (§11.12.5), whatever else the
		// response asks for.
		stale := t.dropRefused(res, resource, presented)
		reqmt, perr := ParseRequirement(res.Header.Get(HeaderRequirement))
		if perr != nil {
			if !stale {
				return res, nil // a 401 that is not an AAuth challenge — the caller's
			}
			drainBody(res.Body)
			if cred, err = t.credential(ctx, resource); err != nil {
				return nil, err
			}
			continue
		}
		drainBody(res.Body)
		switch reqmt.Requirement {
		case RequirementAgentToken:
			// §6.1: the resource wants the agent token itself.
			cred = ""
		case RequirementPersonToken:
			// §6.4: obtain a person token for this resource from the PS.
			if t.PS == nil {
				return nil, fmt.Errorf("aauth: resource at %s requires a person token (requirement=%s) but Transport.PS is not configured", resource, RequirementPersonToken)
			}
			t.markPerson(resource)
			if typ, terr := TokenType(presented); terr == nil && typ == TypPerson {
				// The resource refused the person token we presented.
				t.PS.ForgetPersonTokens(resource)
			}
			if cred, err = t.personToken(ctx, resource); err != nil {
				return nil, err
			}
		case RequirementAuthToken:
			// §6.5: verify the challenge, redeem it at the PS, retry.
			if cred, err = t.authorize(ctx, resource, reqmt.ResourceToken, presented); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("aauth: unsupported requirement %q from %s", reqmt.Requirement, resource)
		}
	}
	return nil, fmt.Errorf("aauth: %s answered more than %d requirements for one request", resource, maxChallenges)
}

// authorize handles requirement=auth-token for resource (draft -11 §6.5):
// it verifies the resource token against the token the agent presented
// (§6.7.3), redeems it at the PS with that token as presented_token
// (§7.2.1, passing a login_hint the resource token carries unchanged),
// checks the auth token it receives (§9.4.4), and caches it.
func (t *Transport) authorize(ctx context.Context, resource, resourceToken, presented string) (string, error) {
	if t.PS == nil {
		return "", fmt.Errorf("aauth: resource at %s requires an auth token but Transport.PS is not configured", resource)
	}
	if !isPresentable(presented) {
		// A resource issues a resource token only against a verified
		// person or auth token (§6.7); this request carried neither.
		return "", fmt.Errorf("aauth: resource at %s sent an auth-token challenge to a request that presented no person or auth token", resource)
	}
	rc, err := VerifyResourceChallenge(ctx, resourceToken, t.challengeOptions(resource, presented))
	if err != nil {
		return "", fmt.Errorf("aauth: challenge from %s: %w", resource, err)
	}
	subagent, err := t.subagentToken()
	if err != nil {
		return "", err
	}
	grant, err := t.PS.RequestAuthToken(ctx, AuthTokenRequest{
		ResourceToken:     resourceToken,
		PresentedToken:    presented,
		UpstreamToken:     t.UpstreamToken,
		SubagentToken:     subagent,
		TokenRequestHints: TokenRequestHints{LoginHint: rc.LoginHint},
	})
	if err != nil {
		return "", err
	}
	if err := t.checkUpstreamBound(grant.AuthToken); err != nil {
		return "", fmt.Errorf("aauth: auth token for %s: %w", resource, err)
	}
	if _, err := VerifyAuthTokenResponse(ctx, grant.AuthToken, AuthResponseVerifyOptions{
		TokenVerifyOptions: t.AuthVerify, Resource: rc, Agent: t.Agent, Presented: presented,
	}); err != nil {
		return "", fmt.Errorf("aauth: auth token for %s: %w", resource, err)
	}
	t.markPerson(resource)
	t.storeAuth(resource, grant)
	return grant.AuthToken, nil
}

// personToken obtains a person token for resource through the PS cache:
// under the mission, or for the upstream token's person in call chaining,
// and for a sub-agent through its parent.
func (t *Transport) personToken(ctx context.Context, resource string) (string, error) {
	req := PersonTokenRequest{Resource: resource, MissionS256: t.MissionS256, UpstreamToken: t.UpstreamToken}
	if t.UpstreamToken != "" {
		req.MissionS256 = "" // the upstream token carries the mission (§7.1)
	}
	var err error
	if req.SubagentToken, err = t.subagentToken(); err != nil {
		return "", err
	}
	tok, err := t.PS.PersonToken(ctx, req)
	if err != nil {
		return "", err
	}
	if err := t.checkUpstreamBound(tok); err != nil {
		return "", err
	}
	return tok, nil
}

// subagentToken is the agent's own token when it is a sub-agent — sent as
// subagent_token by its parent's PS client (§10.2.3) — else "".
func (t *Transport) subagentToken() (string, error) {
	if !t.Agent.ID.IsSubAgent() {
		return "", nil
	}
	if t.PS.Agent == t.Agent {
		return "", ErrSubAgentDirect
	}
	return t.Agent.MintToken()
}

// checkUpstreamBound fails when the upstream token has expired, or when
// token — a downstream person or auth token — outlives it (§10.1.1).
func (t *Transport) checkUpstreamBound(token string) error {
	if t.UpstreamExpiresAt.IsZero() {
		return nil
	}
	if !time.Now().Before(t.UpstreamExpiresAt) {
		return fmt.Errorf("%w: the upstream token expired; use a later token from the calling agent (§10.1.1)", ErrExpired)
	}
	if exp := tokenExpiry(token, 0); exp.After(t.UpstreamExpiresAt) {
		return fmt.Errorf("%w: downstream token outlives the upstream token", ErrUnexpectedToken)
	}
	return nil
}

// isPresentable reports whether token is a person token or an auth token —
// what a resource token's presented_jti can name.
func isPresentable(token string) bool {
	typ, err := TokenType(token)
	return err == nil && (typ == TypPerson || typ == TypAuth)
}

// challengeOptions configures §6.7.3 verification of a challenge from
// resource to a request that presented presented: the resource token's ps
// must be the PS this transport obtains tokens from.
func (t *Transport) challengeOptions(resource, presented string) ResourceChallengeOptions {
	opts := ResourceChallengeOptions{
		TokenVerifyOptions: t.ResourceVerify,
		Resource:           resource,
		Agent:              t.Agent,
		PS:                 t.PS.Issuer(),
		Presented:          presented,
	}
	if opts.Resolver == nil {
		opts.Resolver = JWKSResolver{}
	}
	return opts
}

// sign clones req, attaches credential (the agent token when empty) and
// the optional session token, and signs it, returning the signed request
// and the credential it presents.
func (t *Transport) sign(req *http.Request, body []byte, credential, session string) (*http.Request, string, error) {
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
			return nil, "", err
		}
		credential = tok
	}
	AttachSignatureKey(c, credential)
	if session != "" {
		c.Header.Set("Authorization", "AAuth "+session)
	}
	if err := SignRequest(c, t.Agent.Key, ""); err != nil {
		return nil, "", err
	}
	return c, credential, nil
}

// resend clones an already-signed request with a fresh body reader, to
// present the same signature again.
func resend(signed *http.Request, body []byte) *http.Request {
	c := signed.Clone(signed.Context())
	if body != nil {
		c.Body = io.NopCloser(bytes.NewReader(body))
	}
	return c
}

// followDeferred drives a resource's 202 deferred responses (§6.2, §6.5.1,
// §11.8) with signed polls. A requirement=auth-token on a 202 is satisfied
// in place: the agent obtains an auth token against the token it last
// presented and presents it on the following polls; the resource executes
// the held invocation on the first poll that carries it.
func (t *Transport) followDeferred(req *http.Request, res *http.Response, resource, presented string) (*http.Response, error) {
	if res.StatusCode != http.StatusAccepted {
		return res, nil
	}
	ctx := req.Context()
	current := presented
	return FollowDeferred(ctx, &http.Client{Transport: t.base()}, req.URL, res, DeferredOptions{
		OnRequirement: func(r Requirement) {
			if r.Requirement != RequirementAuthToken && t.OnRequirement != nil {
				t.OnRequirement(r)
			}
		},
		HandleRequirement: func(r Requirement) error {
			if r.Requirement != RequirementAuthToken {
				return nil
			}
			tok, err := t.authorize(ctx, resource, r.ResourceToken, current)
			if err != nil {
				return err
			}
			current = tok
			return nil
		},
		Sign: func(poll *http.Request) error {
			AttachSignatureKey(poll, current)
			return SignRequest(poll, t.Agent.Key, "")
		},
	})
}

// clockSkewWait reports, for a 401 Signature-Error clock_skew, how long to
// wait before presenting the same signed request again (signature-key
// §5.4.14): the amount by which the later of the signature's created and
// the presented token's iat is ahead of the response's Date, less the
// default validity window, plus a second of Date resolution. ok is false
// when the response is not clock_skew, carries no Date, or the wait
// exceeds MaxClockSkewWait.
func (t *Transport) clockSkewWait(res *http.Response, signed *http.Request, presented string) (time.Duration, bool) {
	se, err := SignatureErrorFromResponse(res)
	if err != nil || se == nil || se.Code != SigErrClockSkew {
		return 0, false
	}
	maxWait := t.MaxClockSkewWait
	switch {
	case maxWait < 0:
		return 0, false
	case maxWait == 0:
		maxWait = 10 * time.Second
	}
	date, err := http.ParseTime(res.Header.Get("Date"))
	if err != nil {
		return 0, false
	}
	var ahead time.Time
	if si, err := parseSignatureInput(signed, DefaultSignatureLabel); err == nil && si.created != nil {
		ahead = time.Unix(*si.created, 0)
	}
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(presented, &rc); err == nil && rc.IssuedAt != nil && rc.IssuedAt.After(ahead) {
		ahead = rc.IssuedAt.Time
	}
	wait := max(ahead.Sub(date)-DefaultSignatureWindow+time.Second, 0)
	if wait > maxWait {
		return 0, false
	}
	return wait, true
}

// dropRefused handles a 401 Signature-Error expired_jwt or revoked_jwt for
// a cached token the request presented (§7.9.1 reactive renewal,
// §11.12.5): the auth token or person token is dropped from its cache. It
// reports whether one was.
func (t *Transport) dropRefused(res *http.Response, resource, presented string) bool {
	se, err := SignatureErrorFromResponse(res)
	if err != nil || se == nil || (se.Code != SigErrExpiredJWT && se.Code != SigErrRevokedJWT) {
		return false
	}
	typ, err := TokenType(presented)
	if err != nil {
		return false
	}
	switch typ {
	case TypAuth:
		t.mu.Lock()
		defer t.mu.Unlock()
		if ct, ok := t.auth[resource]; ok && ct.token == presented {
			delete(t.auth, resource)
			return true
		}
	case TypPerson:
		if t.PS != nil {
			t.PS.ForgetPersonTokens(resource)
			return true
		}
	}
	return false
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

func (t *Transport) bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	limit := t.MaxBodyBytes
	if limit <= 0 {
		limit = 4 << 20
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	closeBody(req.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("aauth: request body exceeds Transport.MaxBodyBytes (%d)", limit)
	}
	return b, nil
}

func (t *Transport) refreshMargin() time.Duration {
	if t.RefreshMargin > 0 {
		return t.RefreshMargin
	}
	return DefaultRefreshMargin
}

// credential is the token to present first to resource, top-down (§7.9.1):
// an auth token with more than the refresh margin left; else, for a
// resource that has asked for the person, a person token from the PS
// cache (itself refreshed within the margin); else "" — the agent token,
// minted fresh.
func (t *Transport) credential(ctx context.Context, resource string) (string, error) {
	t.mu.Lock()
	ct, ok := t.auth[resource]
	wantsPerson := t.persons[resource]
	t.mu.Unlock()
	if ok && time.Now().Add(t.refreshMargin()).Before(ct.exp) {
		return ct.token, nil
	}
	if wantsPerson && t.PS != nil {
		return t.personToken(ctx, resource)
	}
	return "", nil
}

// markPerson records that resource needs the person's identity, so later
// requests present a person token rather than the agent token.
func (t *Transport) markPerson(resource string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.persons == nil {
		t.persons = map[string]bool{}
	}
	t.persons[resource] = true
}

func (t *Transport) storeAuth(resource string, grant *AuthTokenResponse) {
	exp := tokenExpiry(grant.AuthToken, grant.ExpiresIn)
	if exp.IsZero() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.auth == nil {
		t.auth = map[string]cachedToken{}
	}
	t.auth[resource] = cachedToken{token: grant.AuthToken, exp: exp}
}

func (t *Transport) cachedSession(resource string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session[resource]
}

// observeSession implements session token rolling refresh (§6.3): a new
// AAuth-Access value on any response replaces the cached session token.
func (t *Transport) observeSession(resource string, res *http.Response) {
	vals := res.Header.Values(HeaderAAuthAccess)
	if len(vals) != 1 {
		return // absent, or multiple credentials (MUST reject) — ignore
	}
	v := strings.TrimSpace(vals[0])
	if v == "" || strings.ContainsAny(v, " \t") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return // not a token68 — reject per §6.3
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		t.session = map[string]string{}
	}
	t.session[resource] = v
}
