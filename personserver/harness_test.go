package personserver

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/golang-jwt/jwt/v5"
)

// world is a test deployment: a PS (the server under test) and a resource
// on httptest servers, and a self-hosted agent whose provider key the PS
// pins. The PS's Decider is the world's decide function, which tests swap.
type world struct {
	t        *testing.T
	ps       *Server
	psURL    string
	store    *MemoryStore
	agent    *aauth.Agent
	resKey   *aauth.Agent // the resource's signing identity
	resURL   string
	scope    string       // what the resource requests
	audience string       // the resource token's aud; empty means the PS
	asKey    *aauth.Agent // the test access server's key, when federating
	resource http.Handler

	mu      sync.Mutex
	decide  func(*TokenRequest) Decision
	clock   time.Time // zero: real time
	notify  func(*Pending)
	cfgHook func(*Config)
	extra   aauth.StaticResolver // more pinned agent issuers
}

const agentIssuer = "https://agent.example"

func newAgent(t *testing.T, local, issuer, ps string) *aauth.Agent {
	t.Helper()
	id, err := aauth.ParseAgentIdentifier("aauth:" + local + "@" + strings.TrimPrefix(issuer, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := aauth.NewAgent(id, aauth.WithIssuer(issuer), aauth.WithPersonServer(ps))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newWorld starts the PS and the resource. hook, when set, adjusts the PS
// configuration before the server is built.
func newWorld(t *testing.T, hook func(*Config)) *world {
	t.Helper()
	w := &world{t: t, store: NewMemoryStore(), scope: "files:read", extra: aauth.StaticResolver{}, cfgHook: hook}
	w.decide = func(r *TokenRequest) Decision { return Allow(Grant{Person: "alice"}) }

	var psHandler http.Handler
	psSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { psHandler.ServeHTTP(rw, r) }))
	t.Cleanup(psSrv.Close)
	w.psURL = psSrv.URL

	var err error
	w.agent = newAgent(t, "assistant", agentIssuer, w.psURL)
	if w.resKey, err = aauth.NewAgent(aauth.AgentIdentifier{Name: "res", Domain: "files.example"}); err != nil {
		t.Fatal(err)
	}
	resSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { w.resource.ServeHTTP(rw, r) }))
	t.Cleanup(resSrv.Close)
	w.resURL = resSrv.URL
	w.resource = w.serveResource()

	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Issuer:     w.psURL,
		Key:        key,
		SubjectKey: bytes.Repeat([]byte{7}, 32),
		Store:      w.store,
		Decider: DeciderFunc(func(_ context.Context, r *TokenRequest) (Decision, error) {
			w.mu.Lock()
			fn := w.decide
			w.mu.Unlock()
			return fn(r), nil
		}),
		InteractionURL: "https://ps.example/interact",
		AgentResolver:  w.agentResolver(),
		TokenResolver:  aauth.StaticResolver{w.resURL: w.resKey.JWKS()},
		HTTPClient:     psSrv.Client(),
		Notify: func(_ context.Context, p *Pending) {
			w.mu.Lock()
			fn := w.notify
			w.mu.Unlock()
			if fn != nil {
				fn(p)
			}
		},
		Now: func() time.Time {
			w.mu.Lock()
			defer w.mu.Unlock()
			if w.clock.IsZero() {
				return time.Now()
			}
			return w.clock
		},
		InsecureSkipIdentifierCheck: true,
	}
	if hook != nil {
		hook(&cfg)
	}
	if w.ps, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	psHandler = w.ps
	return w
}

// agentResolver pins the world's agent provider and any extra issuers.
func (w *world) agentResolver() aauth.KeyResolver {
	return resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
		w.mu.Lock()
		set, ok := w.extra[iss]
		w.mu.Unlock()
		if ok {
			return aauth.StaticResolver{iss: set}.ResolveKey(ctx, iss, dwk, kid, cnf)
		}
		return aauth.StaticResolver{agentIssuer: w.agent.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
	})
}

// otherAgent is another self-hosted agent, with its own provider pinned.
func (w *world) otherAgent(local string) *aauth.Agent {
	a := newAgent(w.t, local, "https://"+local+".example", w.psURL)
	w.pin(a.Issuer, a.JWKS())
	return a
}

// pin adds a self-hosted agent provider the PS trusts.
func (w *world) pin(iss string, set aauth.JWKS) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra[iss] = set
}

func (w *world) setDecide(fn func(*TokenRequest) Decision) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.decide = fn
}

func (w *world) setNotify(fn func(*Pending)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notify = fn
}

func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.clock.IsZero() {
		w.clock = time.Now()
	}
	w.clock = w.clock.Add(d)
}

// psClient is a PS client for agent with short polling.
func (w *world) psClient(agent *aauth.Agent) *aauth.PSClient {
	c := aauth.NewPSClient(w.psURL, agent)
	c.PreferWaitSeconds = 2
	if _, err := c.Discover(context.Background()); err != nil {
		w.t.Fatal(err)
	}
	return c
}

// transport is an agent Transport against the world.
func (w *world) transport(agent *aauth.Agent, ps *aauth.PSClient) *aauth.Transport {
	tr := aauth.NewTransport(agent, ps)
	tr.ResourceVerify = aauth.TokenVerifyOptions{Resolver: aauth.StaticResolver{w.resURL: w.resKey.JWKS()}, InsecureSkipIdentifierCheck: true}
	tr.AuthVerify = w.psOpts()
	return tr
}

// psOpts verify tokens the PS issued.
func (w *world) psOpts() aauth.TokenVerifyOptions {
	r := aauth.StaticResolver{w.psURL: w.ps.JWKS()}
	if w.asKey != nil {
		r[testAS] = w.asKey.JWKS()
	}
	return aauth.TokenVerifyOptions{Resolver: r, InsecureSkipIdentifierCheck: true}
}

// serveResource is a resource that serves on an auth token, challenges a
// person token for one, and an agent token for a person token.
func (w *world) serveResource() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		tok, err := aauth.ParseSignatureKey(r)
		if err != nil {
			aauth.WriteSignatureFailure(rw, err)
			return
		}
		typ, _ := aauth.TokenType(tok)
		switch typ {
		case aauth.TypAuth:
			claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, w.resURL, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: w.psOpts()})
			if err != nil {
				aauth.WriteSignatureFailure(rw, err)
				return
			}
			_, _ = io.WriteString(rw, "hello "+claims.Subject+" scope="+claims.Scope)
		case aauth.TypPerson:
			person, err := aauth.VerifyAndExtractPerson(r.Context(), r, w.resURL, w.psOpts())
			if err != nil {
				aauth.WriteSignatureFailure(rw, err)
				return
			}
			rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: w.resURL, Scope: w.scope, Audience: w.audience}, person, w.resKey.Key, w.resKey.JWK().Kid)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			aauth.ChallengeAuthToken(rw, rt)
		default:
			aauth.ChallengePersonToken(rw)
		}
	})
}

// personToken obtains a person token for resource for agent directly.
func (w *world) personToken(agent *aauth.Agent, resource, mission string) string {
	w.t.Helper()
	tok, err := w.psClient(agent).PersonToken(context.Background(), aauth.PersonTokenRequest{Resource: resource, MissionS256: mission})
	if err != nil {
		w.t.Fatal(err)
	}
	return tok
}

// resourceToken mints a resource token at the world's resource against the
// presented token (verified first), as the resource would.
func (w *world) resourceToken(presented string, p aauth.ResourceTokenParams) string {
	w.t.Helper()
	if p.Resource == "" {
		p.Resource = w.resURL
	}
	var pt aauth.PresentedToken
	typ, _ := aauth.TokenType(presented)
	opts := aauth.TokenVerifyOptions{Resolver: w.ps.tokens, InsecureSkipIdentifierCheck: true}
	var err error
	if typ == aauth.TypPerson {
		pt, err = aauth.VerifyPersonToken(context.Background(), presented, p.Resource, opts)
	} else {
		pt, err = aauth.VerifyAuthToken(context.Background(), presented, p.Resource, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: opts})
	}
	if err != nil {
		w.t.Fatal(err)
	}
	rt, err := aauth.IssueResourceToken(p, pt, w.resKey.Key, w.resKey.JWK().Kid)
	if err != nil {
		w.t.Fatal(err)
	}
	return rt
}

// signed sends a signed request to the PS as agent (presenting token, or
// a fresh agent token when empty) and returns the response.
func (w *world) signed(agent *aauth.Agent, token, method, path string, body any) *http.Response {
	w.t.Helper()
	var rd io.Reader
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			w.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, w.psURL+path, rd)
	if err != nil {
		w.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token == "" {
		if token, err = agent.MintToken(); err != nil {
			w.t.Fatal(err)
		}
	}
	aauth.AttachSignatureKey(req, token)
	if err := aauth.SignRequest(req, agent.Key, ""); err != nil {
		w.t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

// errorCode reads the error member of a problem body and closes it.
func errorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var b struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(raw, &b)
	return b.Error
}

// tokenCode returns the token endpoint error code of err, or "".
func tokenCode(err error) string {
	var te *aauth.TokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

type resolverFunc func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error)

func (f resolverFunc) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	return f(ctx, iss, dwk, kid, cnf)
}

func parseUnverified(tok string, dst jwt.Claims) error {
	_, _, err := jwt.NewParser().ParseUnverified(tok, dst)
	return err
}
