package accessserver

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// Paths are the URL paths the AS serves, relative to its issuer. The
// metadata document is always /.well-known/aauth-access.json. The
// defaults live under /as/ so an AS can share an origin with a PS and an
// agent provider (§9.3.3).
type Paths struct {
	JWKS       string
	Token      string
	Revocation string
	// Pending is the prefix of pending URLs.
	Pending string
}

// DefaultPaths returns the default endpoint paths.
func DefaultPaths() Paths {
	return Paths{JWKS: "/as/jwks.json", Token: "/as/token", Revocation: "/as/revoke", Pending: "/as/pending/"}
}

func (p Paths) withDefaults() Paths {
	d := DefaultPaths()
	if p.JWKS == "" {
		p.JWKS = d.JWKS
	}
	if p.Token == "" {
		p.Token = d.Token
	}
	if p.Revocation == "" {
		p.Revocation = d.Revocation
	}
	if p.Pending == "" {
		p.Pending = d.Pending
	}
	if !strings.HasSuffix(p.Pending, "/") {
		p.Pending += "/"
	}
	return p
}

// Config configures a [Server]. Issuer, Key, Store, and Authorizer are
// required.
type Config struct {
	// Issuer is the AS's server identifier: the iss of the auth tokens it
	// issues, and the aud of the resource tokens it redeems.
	Issuer string
	// Key signs auth tokens and the AS's own requests; KeyID is its kid
	// (default: the RFC 7638 thumbprint). PublishedKeys are extra keys to
	// publish, for rotation.
	Key           crypto.Signer
	KeyID         string
	PublishedKeys []aauth.JWK
	// Store persists issued tokens, revocations, and pending requests.
	Store Store
	// Authorizer decides token requests.
	Authorizer Authorizer
	// Resources, when set, reports whether the AS serves the resource
	// (the resource token's iss); others are invalid_resource_token.
	Resources func(resource string) bool
	// TrustPS, when set, decides whether a verified PS may request tokens
	// at all; refused ones are answered 403 denied. Nil admits every PS
	// whose signature verifies — trust then emerges from the Authorizer
	// (claims, interaction; §9.3.1).
	TrustPS func(ctx context.Context, ps string) bool
	// InteractionURL is the AS's user-facing interaction page, for
	// requirement=interaction decisions; it calls [Server.ConsumeCode].
	InteractionURL string
	// Paths overrides endpoint paths.
	Paths Paths
	// Metadata supplies display members of the metadata document.
	Metadata aauth.ServerMetadata
	// ServerResolver resolves PS keys (jwks_uri scheme); TokenResolver
	// resolves resource token and person token keys; AgentResolver
	// resolves agent token keys. Each defaults to JWKS discovery through
	// HTTPClient. Tokens this AS issued are verified against its own keys.
	ServerResolver aauth.KeyResolver
	TokenResolver  aauth.KeyResolver
	AgentResolver  aauth.KeyResolver
	// HTTPClient makes outbound requests; nil uses http.DefaultClient.
	HTTPClient *http.Client
	// Revoker delivers the AS's revocations to resources; nil discovers
	// each resource's revocation endpoint and signs as the AS.
	Revoker Revoker
	// AcceptRevocation, when set, decides whether a verified PS or
	// resource may revoke here; refused callers get unsupported_iss.
	AcceptRevocation func(ctx context.Context, caller aauth.ServerCaller) bool
	// AuthTokenTTL is the default auth token lifetime (at most one hour).
	AuthTokenTTL time.Duration
	// SignatureWindow, PendingTTL (default ten minutes), MaxWait (default
	// 30 seconds), and MaxClarificationRounds (default five) tune requests
	// and deferred responses.
	SignatureWindow        time.Duration
	PendingTTL             time.Duration
	MaxWait                time.Duration
	MaxClarificationRounds int
	// Limiter, when set, limits polls per pending request ("poll:",
	// answered slow_down) and revocations per issuer ("revoke:", answered
	// rate_limited with Retry-After).
	Limiter aauth.Limiter
	// Notify is called after a pending request is created or changes.
	Notify func(ctx context.Context, p *Pending)
	// Logger receives operational errors; nil discards them.
	Logger *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// InsecureSkipIdentifierCheck accepts identifiers that are not server
	// identifiers, for development and tests. Never set it in production.
	InsecureSkipIdentifierCheck bool
}

// Server is an Access Server (draft -11 §9): an http.Handler serving the
// AS token endpoint, pending URLs, the revocation endpoint, the metadata
// document, and the JWKS.
type Server struct {
	cfg     Config
	paths   Paths
	kid     string
	jwks    aauth.JWKS
	tokens  aauth.KeyResolver
	agents  aauth.KeyResolver
	servers aauth.KeyResolver
	mux     *http.ServeMux
	waiters waiters
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("accessserver: Config.Issuer is required")
	case cfg.Key == nil:
		return nil, errors.New("accessserver: Config.Key is required")
	case cfg.Store == nil:
		return nil, errors.New("accessserver: Config.Store is required")
	case cfg.Authorizer == nil:
		return nil, errors.New("accessserver: Config.Authorizer is required")
	}
	if !cfg.InsecureSkipIdentifierCheck {
		if err := aauth.ValidateServerIdentifier(cfg.Issuer); err != nil {
			return nil, fmt.Errorf("accessserver: Config.Issuer: %w", err)
		}
	}
	jwk, err := aauth.NewJWK(cfg.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("accessserver: Config.Key: %w", err)
	}
	if cfg.KeyID != "" {
		jwk.Kid = cfg.KeyID
	}
	s := &Server{cfg: cfg, paths: cfg.Paths.withDefaults(), kid: jwk.Kid}
	s.jwks = aauth.JWKS{Keys: append([]aauth.JWK{jwk}, cfg.PublishedKeys...)}
	discover := func(r aauth.KeyResolver) aauth.KeyResolver {
		if r != nil {
			return r
		}
		return aauth.NewJWKSResolver(cfg.HTTPClient)
	}
	s.tokens = selfResolver{issuer: cfg.Issuer, keys: s.jwks, next: discover(cfg.TokenResolver)}
	s.agents = discover(cfg.AgentResolver)
	s.servers = discover(cfg.ServerResolver)
	s.mux = http.NewServeMux()
	s.Register(s.mux)
	return s, nil
}

// ServeHTTP serves the AS routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Register adds the AS routes to mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/"+aauth.WellKnownAccess, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Metadata())
	})
	mux.HandleFunc("GET "+s.paths.JWKS, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeJSON(w, http.StatusOK, s.jwks)
	})
	mux.HandleFunc("POST "+s.paths.Token, s.serveToken)
	mux.HandleFunc(s.paths.Pending+"{id}", s.servePending)
	mux.HandleFunc("POST "+s.paths.Revocation, s.serveRevocation)
}

// Issuer returns the AS's issuer.
func (s *Server) Issuer() string { return s.cfg.Issuer }

// JWKS returns the key set the AS publishes.
func (s *Server) JWKS() aauth.JWKS { return s.jwks }

// Signer returns the AS's server signer (§11.3.2).
func (s *Server) Signer() aauth.ServerSigner {
	return aauth.ServerSigner{Issuer: s.cfg.Issuer, DWK: aauth.WellKnownAccess, Kid: s.kid, Key: s.cfg.Key}
}

// Metadata returns the AS metadata document (§11.2.3).
func (s *Server) Metadata() aauth.AccessServerMetadata {
	md := aauth.AccessServerMetadata{ServerMetadata: s.cfg.Metadata}
	md.Issuer = s.cfg.Issuer
	md.JWKSURI = s.url(s.paths.JWKS)
	md.AuthTokenEndpoint = s.url(s.paths.Token)
	md.RevocationEndpoint = s.url(s.paths.Revocation)
	return md
}

func (s *Server) url(path string) string { return strings.TrimSuffix(s.cfg.Issuer, "/") + path }

func (s *Server) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

func (s *Server) logger() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Server) signatureOptions(at time.Time) aauth.RequestVerifyOptions {
	return aauth.RequestVerifyOptions{Window: s.cfg.SignatureWindow, RequireBodyCoverage: true, Now: func() time.Time { return at }}
}

func (s *Server) tokenOptions(at time.Time) aauth.TokenVerifyOptions {
	return aauth.TokenVerifyOptions{Resolver: s.tokens, Signature: s.signatureOptions(at), InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck}
}

func (s *Server) agentOptions(at time.Time) aauth.VerifyAgentTokenOptions {
	return aauth.VerifyAgentTokenOptions{Resolver: s.agents, RequireProviderClaims: !s.cfg.InsecureSkipIdentifierCheck, Signature: s.signatureOptions(at)}
}

// selfResolver resolves this AS's own keys locally.
type selfResolver struct {
	issuer string
	keys   aauth.JWKS
	next   aauth.KeyResolver
}

func (r selfResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	if iss == r.issuer && dwk == aauth.WellKnownAccess {
		return aauth.StaticResolver{iss: r.keys}.ResolveKey(ctx, iss, dwk, kid, cnf)
	}
	return r.next.ResolveKey(ctx, iss, dwk, kid, cnf)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(v)
}

// waiters wakes requests held for Prefer: wait.
type waiters struct {
	mu sync.Mutex
	m  map[string][]chan struct{}
}

func (w *waiters) subscribe(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		w.m = map[string][]chan struct{}{}
	}
	w.m[id] = append(w.m[id], ch)
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		list := w.m[id]
		for i, c := range list {
			if c == ch {
				w.m[id] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(w.m[id]) == 0 {
			delete(w.m, id)
		}
	}
}

func (w *waiters) notify(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ch := range w.m[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Server) allow(ctx context.Context, key string) (bool, time.Duration) {
	if s.cfg.Limiter == nil {
		return true, 0
	}
	return s.cfg.Limiter.Allow(ctx, key)
}

// retrySeconds renders a Retry-After value, rounding up to whole seconds.
func retrySeconds(d time.Duration) string {
	return strconv.Itoa(int(max((d+time.Second-1)/time.Second, 1)))
}
