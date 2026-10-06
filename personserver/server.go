package personserver

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// Paths are the URL paths the PS serves, relative to its issuer. The
// metadata document is always at /.well-known/aauth-person.json. The
// defaults live under /ps/ so a PS can share an origin with an agent
// provider and an access server (role collocation, §4.3).
type Paths struct {
	JWKS        string
	PersonToken string
	AuthToken   string
	Mission     string
	Permission  string
	Audit       string
	Interaction string
	Revocation  string
	// Pending is the prefix of pending URLs; a pending request's URL is
	// Pending + id.
	Pending string
}

// DefaultPaths returns the default endpoint paths.
func DefaultPaths() Paths {
	return Paths{
		JWKS:        "/ps/jwks.json",
		PersonToken: "/ps/person",
		AuthToken:   "/ps/token",
		Mission:     "/ps/mission",
		Permission:  "/ps/permission",
		Audit:       "/ps/audit",
		Interaction: "/ps/interaction",
		Revocation:  "/ps/revoke",
		Pending:     "/ps/pending/",
	}
}

func (p Paths) withDefaults() Paths {
	d := DefaultPaths()
	for _, f := range []struct {
		dst *string
		def string
	}{
		{&p.JWKS, d.JWKS}, {&p.PersonToken, d.PersonToken}, {&p.AuthToken, d.AuthToken},
		{&p.Mission, d.Mission}, {&p.Permission, d.Permission}, {&p.Audit, d.Audit},
		{&p.Interaction, d.Interaction}, {&p.Revocation, d.Revocation}, {&p.Pending, d.Pending},
	} {
		if *f.dst == "" {
			*f.dst = f.def
		}
	}
	if !strings.HasSuffix(p.Pending, "/") {
		p.Pending += "/"
	}
	return p
}

// Config configures a [Server]. Issuer, Key, SubjectKey, Store, and
// Decider are required.
type Config struct {
	// Issuer is the PS's server identifier (§11.1.1): the iss of the
	// tokens it issues and the base of its endpoint URLs.
	Issuer string
	// Key signs person and auth tokens and server-signed requests; KeyID
	// is its kid in the PS's JWKS (default: the key's RFC 7638
	// thumbprint). When one origin hosts several roles, give each its own
	// key: each role publishes its own metadata and JWKS (§9.3.3).
	Key   crypto.Signer
	KeyID string
	// PublishedKeys are extra keys to publish in the JWKS, for rotation.
	PublishedKeys []aauth.JWK
	// SubjectKey keys the derivation of directed identifiers (see
	// [DirectedSubject]); at least 32 bytes, stable for the PS's lifetime.
	SubjectKey []byte
	// Store persists PS state. Required.
	Store Store
	// Decider decides person and auth token requests. Required.
	Decider Decider
	// MissionApprover enables the mission endpoint (§8).
	MissionApprover MissionApprover
	// PermissionDecider enables the permission endpoint (§7.7).
	PermissionDecider PermissionDecider
	// InteractionRelay enables the interaction endpoint (§7.6).
	InteractionRelay InteractionRelay
	// Audit enables the audit endpoint (§7.8). Records go to the mission
	// log; AuditSink, when set, also receives them.
	Audit     bool
	AuditSink func(ctx context.Context, agent AgentRef, r aauth.AuditRequest)
	// Federator enables four-party access (§9.1): resource tokens
	// addressed to an access server are federated through it. Without
	// one, such resource tokens are refused. ClaimsProvider answers the
	// identity claims an access server requires (§9.2).
	Federator      Federator
	ClaimsProvider ClaimsProvider
	// InteractionURL is the PS's user-facing interaction page (https, no
	// query or fragment), sent as the url of requirement=interaction. The
	// page reads ?code= and calls [Server.ConsumeCode]. Required for
	// requirement=interaction decisions.
	InteractionURL string
	// Paths overrides endpoint paths; zero fields take DefaultPaths.
	Paths Paths
	// Metadata supplies the display members of the metadata document
	// (name, description, logos, ...); issuer, jwks_uri, and the endpoints
	// are filled in.
	Metadata aauth.ServerMetadata
	// ScopesSupported, ClaimsSupported, and MissionControlEndpoint are
	// published in the metadata document when set.
	ScopesSupported        []string
	ClaimsSupported        []string
	MissionControlEndpoint string
	// AgentResolver resolves agent token keys; nil discovers them at
	// {iss}/.well-known/aauth-agent.json through HTTPClient.
	AgentResolver aauth.KeyResolver
	// TokenResolver resolves resource token keys and access-server auth
	// token keys; nil discovers them through HTTPClient. Tokens this PS
	// issued are always verified against its own keys.
	TokenResolver aauth.KeyResolver
	// ServerResolver resolves the keys of servers signing under the
	// jwks_uri scheme (revocations); nil discovers them through HTTPClient.
	ServerResolver aauth.KeyResolver
	// AcceptRevocation, when set, decides whether a verified agent
	// provider or resource may revoke at this PS; refused callers get
	// unsupported_iss (§11.12.3). Nil accepts every verified caller.
	AcceptRevocation func(ctx context.Context, caller aauth.ServerCaller) bool
	// Revoker delivers the PS's own revocations downstream; nil uses an
	// HTTPRevoker signing as the PS.
	Revoker Revoker
	// HTTPClient makes outbound requests (discovery, revocation); nil uses
	// http.DefaultClient. Deployments SHOULD apply egress admission.
	HTTPClient *http.Client
	// SignatureWindow is the HTTP signature validity window (default
	// aauth.DefaultSignatureWindow).
	SignatureWindow time.Duration
	// PendingTTL bounds how long a deferred request stays open (default
	// ten minutes); MaxWait caps how long a request is held for Prefer:
	// wait (default 30 seconds).
	PendingTTL time.Duration
	MaxWait    time.Duration
	// MaxClarificationRounds bounds clarification questions per request
	// (§7.5.3; default five).
	MaxClarificationRounds int
	// PersonTokenTTL and AuthTokenTTL are the default token lifetimes
	// (at most one hour; default one hour).
	PersonTokenTTL time.Duration
	AuthTokenTTL   time.Duration
	// Notify, when set, is called after a pending request is created or
	// changes (a clarification answer, an updated request, a resolution),
	// so the hosting application can update its approval UI.
	Notify func(ctx context.Context, p *Pending)
	// Logger receives security events (failed mission lookups, rejected
	// requests); nil discards them.
	Logger *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// InsecureSkipIdentifierCheck accepts identifiers that are not server
	// identifiers (http, ports), for development and tests. It also
	// relaxes the agent-token profile check. Never set it in production.
	InsecureSkipIdentifierCheck bool
}

// Server is a Person Server (draft -11 §7). It is an http.Handler serving
// the PS endpoints, its metadata document, and its JWKS; [Server.Register]
// adds the same routes to a shared mux when one origin hosts several
// roles.
type Server struct {
	cfg      Config
	paths    Paths
	kid      string
	jwks     aauth.JWKS
	tokens   aauth.KeyResolver // resource tokens, AS tokens, and our own
	agents   aauth.KeyResolver
	mux      *http.ServeMux
	waiters  waiters
	subjects subjectDeriver
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("personserver: Config.Issuer is required")
	case cfg.Key == nil:
		return nil, errors.New("personserver: Config.Key is required")
	case cfg.Store == nil:
		return nil, errors.New("personserver: Config.Store is required")
	case cfg.Decider == nil:
		return nil, errors.New("personserver: Config.Decider is required")
	case len(cfg.SubjectKey) < 32:
		return nil, errors.New("personserver: Config.SubjectKey must be at least 32 bytes")
	}
	if !cfg.InsecureSkipIdentifierCheck {
		if err := aauth.ValidateServerIdentifier(cfg.Issuer); err != nil {
			return nil, fmt.Errorf("personserver: Config.Issuer: %w", err)
		}
	}
	jwk, err := aauth.NewJWK(cfg.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("personserver: Config.Key: %w", err)
	}
	if cfg.KeyID != "" {
		jwk.Kid = cfg.KeyID
	}
	s := &Server{cfg: cfg, paths: cfg.Paths.withDefaults(), kid: jwk.Kid}
	s.jwks = aauth.JWKS{Keys: append([]aauth.JWK{jwk}, cfg.PublishedKeys...)}
	s.subjects = subjectDeriver{key: cfg.SubjectKey}
	hc := cfg.HTTPClient
	s.agents = cfg.AgentResolver
	if s.agents == nil {
		s.agents = aauth.NewJWKSResolver(hc)
	}
	external := cfg.TokenResolver
	if external == nil {
		external = aauth.NewJWKSResolver(hc)
	}
	s.tokens = selfResolver{issuer: cfg.Issuer, dwk: aauth.WellKnownPerson, keys: s.jwks, next: external}
	s.mux = http.NewServeMux()
	s.Register(s.mux)
	return s, nil
}

// ServeHTTP serves the PS routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Register adds the PS routes to mux: the metadata document, the JWKS, the
// endpoints, and the pending URLs. Optional endpoints are registered only
// when configured.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/"+aauth.WellKnownPerson, s.serveMetadata)
	mux.HandleFunc("GET "+s.paths.JWKS, s.serveJWKS)
	mux.HandleFunc("POST "+s.paths.PersonToken, s.servePersonToken)
	mux.HandleFunc("POST "+s.paths.AuthToken, s.serveAuthToken)
	mux.HandleFunc(s.paths.Pending+"{id}", s.servePending)
	s.registerGovernance(mux)
}

// Issuer returns the PS's issuer.
func (s *Server) Issuer() string { return s.cfg.Issuer }

// JWKS returns the key set the PS publishes.
func (s *Server) JWKS() aauth.JWKS { return s.jwks }

// Signer returns the server signer the PS uses for requests it makes in
// its own right (revocations, federation; §11.3.2).
func (s *Server) Signer() aauth.ServerSigner {
	return aauth.ServerSigner{Issuer: s.cfg.Issuer, DWK: aauth.WellKnownPerson, Kid: s.kid, Key: s.cfg.Key}
}

// Metadata returns the PS's metadata document (§11.2.2).
func (s *Server) Metadata() aauth.PersonServerMetadata {
	md := aauth.PersonServerMetadata{ServerMetadata: s.cfg.Metadata}
	md.Issuer = s.cfg.Issuer
	md.JWKSURI = s.url(s.paths.JWKS)
	md.PersonTokenEndpoint = s.url(s.paths.PersonToken)
	md.AuthTokenEndpoint = s.url(s.paths.AuthToken)
	md.ScopesSupported = s.cfg.ScopesSupported
	md.ClaimsSupported = s.cfg.ClaimsSupported
	md.MissionControlEndpoint = s.cfg.MissionControlEndpoint
	s.governanceMetadata(&md)
	return md
}

func (s *Server) url(path string) string { return strings.TrimSuffix(s.cfg.Issuer, "/") + path }

func (s *Server) serveMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Metadata())
}

func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "max-age=300")
	writeJSON(w, http.StatusOK, s.jwks)
}

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

// signatureOptions are the HTTP signature checks for agent requests to PS
// endpoints (§11.3.4): content-digest and content-type covered on bodies.
func (s *Server) signatureOptions(at time.Time) aauth.RequestVerifyOptions {
	return aauth.RequestVerifyOptions{
		Window:              s.cfg.SignatureWindow,
		RequireBodyCoverage: true,
		Now:                 func() time.Time { return at },
	}
}

// tokenOptions verify server-issued tokens as of at.
func (s *Server) tokenOptions(at time.Time) aauth.TokenVerifyOptions {
	return aauth.TokenVerifyOptions{
		Resolver:                    s.tokens,
		Signature:                   s.signatureOptions(at),
		InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	}
}

func (s *Server) agentOptions(at time.Time) aauth.VerifyAgentTokenOptions {
	return aauth.VerifyAgentTokenOptions{
		Resolver:              s.agents,
		RequireProviderClaims: !s.cfg.InsecureSkipIdentifierCheck,
		Signature:             s.signatureOptions(at),
	}
}

func (s *Server) checkIdentifier(v string) error {
	if s.cfg.InsecureSkipIdentifierCheck {
		if v == "" {
			return errors.New("empty identifier")
		}
		return nil
	}
	return aauth.ValidateServerIdentifier(v)
}

// selfResolver resolves this server's own keys locally and every other
// issuer through next.
type selfResolver struct {
	issuer, dwk string
	keys        aauth.JWKS
	next        aauth.KeyResolver
}

func (r selfResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	if iss == r.issuer && dwk == r.dwk {
		return aauth.StaticResolver{iss: r.keys}.ResolveKey(ctx, iss, dwk, kid, cnf)
	}
	return r.next.ResolveKey(ctx, iss, dwk, kid, cnf)
}

// waiters wakes requests held for Prefer: wait when a pending request
// changes in this process.
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
