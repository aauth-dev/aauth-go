package agentprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/golang-jwt/jwt/v5"
)

// Paths are the URL paths the agent provider serves, relative to its
// issuer. The metadata document is always /.well-known/aauth-agent.json.
// Bootstrap defines no endpoint paths ("each AP defines its own");
// these defaults live under /ap/ so an AP can share an origin with a PS
// and an AS.
type Paths struct {
	JWKS     string
	Token    string // hwk: enrollment and single-key refresh (bootstrap §8.2)
	Refresh  string // jkt-jwt: two-key refresh (bootstrap §8.1)
	Subagent string // jwt: sub-agent issuance under a hosted AP (bootstrap §9.2)
}

// DefaultPaths returns the default endpoint paths.
func DefaultPaths() Paths {
	return Paths{JWKS: "/ap/jwks.json", Token: "/ap/token", Refresh: "/ap/refresh", Subagent: "/ap/subagent"}
}

// Registration is what the provider issues an agent token with.
type Registration struct {
	// Name is the agent identifier's local part (the domain is the
	// provider's); it must be stable for the agent install (bootstrap §6).
	Name string
	// PS is the person server, carried as the ps claim.
	PS string
	// TTL is the token lifetime (default Config.TokenTTL, at most 24h).
	TTL time.Duration
}

// IssueRequest is an issuance request over HTTP for the key the request
// presented under the hwk scheme, which also signed it.
type IssueRequest struct {
	// Key is the presented public key; the token's cnf.jwk.
	Key aauth.JWK
	// Body is the request body (the AP's own enrollment fields).
	Body json.RawMessage
	// Attestation is the verified platform attestation, when the body
	// carried one (bootstrap §5).
	Attestation *Attestation
}

// RefreshRequest is a two-key refresh (bootstrap §8.1): the durable key
// identified by its thumbprint URI delegated to a fresh ephemeral key.
type RefreshRequest struct {
	Durable     aauth.JWK
	DurableID   string // urn:jkt:sha-256:...
	Ephemeral   aauth.JWK
	Body        json.RawMessage
	Attestation *Attestation
}

// SubagentRequest is a parent's request for a sub-agent token (bootstrap
// §9.2): the parent's verified agent token, the sub-agent's public key,
// and the discriminator it asked for, if any.
type SubagentRequest struct {
	Parent        *aauth.AgentClaims
	Key           aauth.JWK
	Discriminator string
}

// SubagentGrant shapes an authorized sub-agent token.
type SubagentGrant struct {
	// Discriminator overrides the requested one; empty keeps it, or
	// generates one when none was requested.
	Discriminator string
	// TTL is the lifetime; never later than the parent's token.
	TTL time.Duration
}

// Registrar is the hosting application's issuance policy. It decides who
// gets an agent token for which key, so tokens can be tied to the
// application's own records (an enrollment, a work session). Returning an
// error refuses the request (403 denied).
type Registrar interface {
	// AuthorizeIssue authorizes an hwk-signed issuance request; r is the
	// HTTP request, so the application can read its own authentication
	// (a session, a bearer credential) from it.
	AuthorizeIssue(ctx context.Context, r *http.Request, req *IssueRequest) (*Registration, error)
	// AuthorizeRefresh authorizes a two-key refresh: look up the
	// enrollment by DurableID and re-check posture.
	AuthorizeRefresh(ctx context.Context, req *RefreshRequest) (*Registration, error)
	// AuthorizeSubagent applies sub-agent policy: whether this parent may
	// spawn, how many may be live, for how long.
	AuthorizeSubagent(ctx context.Context, req *SubagentRequest) (*SubagentGrant, error)
}

// Attestation is a verified platform attestation result (bootstrap §5).
type Attestation struct {
	Format string         // e.g. "webauthn", "app-attest", "play-integrity"
	Claims map[string]any // what the verifier established
}

// AttestationVerifier verifies the attestation evidence a request body
// carries in its "attestation" member against the key being enrolled.
type AttestationVerifier interface {
	VerifyAttestation(ctx context.Context, evidence json.RawMessage, key aauth.JWK) (*Attestation, error)
}

// IssuedToken is reported to Config.OnIssue for every agent token the
// provider issues: record it to revoke it later (the jti and exp) or to
// count a parent's live sub-agents.
type IssuedToken struct {
	Token  string
	Claims *aauth.AgentClaims
}

// Config configures a [Server]. Issuer and Key are required.
type Config struct {
	// Issuer is the provider's server identifier: the iss of the agent
	// tokens it issues.
	Issuer string
	// Domain is the domain of the agent identifiers it issues; default the
	// issuer's host.
	Domain string
	// Key is the provider's signing key — separate from every agent's key
	// — and KeyID its kid (default: the RFC 7638 thumbprint).
	// PublishedKeys are extra keys to publish, for rotation.
	Key           crypto.Signer
	KeyID         string
	PublishedKeys []aauth.JWK
	// Registrar enables the HTTP endpoints; without it the provider only
	// issues through [Server.IssueAgentToken].
	Registrar Registrar
	// Attestation verifies attestation evidence; without it a request
	// carrying evidence is refused.
	Attestation AttestationVerifier
	// Replay remembers naming-JWT identifiers; nil uses an in-process
	// cache.
	Replay ReplayCache
	// Limiter, when set, limits issuance per presented key ("issue:"),
	// refreshes per durable key ("refresh:"), and sub-agent requests per
	// parent ("subagent:"), answered 429 rate_limited with Retry-After.
	// It is checked after the request authenticates and before the
	// Registrar is asked.
	Limiter aauth.Limiter
	// OnIssue is called for every token issued.
	OnIssue func(ctx context.Context, t IssuedToken)
	// TokenTTL is the default token lifetime (default one hour).
	TokenTTL time.Duration
	// Paths overrides endpoint paths; Metadata supplies display members
	// and callback_endpoint, event_endpoint, and localhost_callback_allowed.
	Paths    Paths
	Metadata aauth.AgentProviderMetadata
	// SignatureWindow is the HTTP signature validity window.
	SignatureWindow time.Duration
	// HTTPClient makes outbound requests (revocation); nil uses
	// aauth.DiscoveryClient, which reaches only public https destinations.
	HTTPClient *http.Client
	// Logger receives operational errors; nil discards them.
	Logger *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Server is a hosted agent provider (draft-hardt-aauth-bootstrap-02): it
// publishes aauth-agent.json and its JWKS, issues agent tokens for keys
// it has authorized, refreshes them by the two-key jkt-jwt ceremony,
// issues sub-agent tokens to parents, and revokes agent tokens at person
// servers.
type Server struct {
	cfg    Config
	paths  Paths
	kid    string
	jwks   aauth.JWKS
	domain string
	replay ReplayCache
	mux    *http.ServeMux
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("agentprovider: Config.Issuer is required")
	case cfg.Key == nil:
		return nil, errors.New("agentprovider: Config.Key is required")
	}
	jwk, err := aauth.NewJWK(cfg.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("agentprovider: Config.Key: %w", err)
	}
	if cfg.KeyID != "" {
		jwk.Kid = cfg.KeyID
	}
	s := &Server{cfg: cfg, kid: jwk.Kid, replay: cfg.Replay}
	s.jwks = aauth.JWKS{Keys: append([]aauth.JWK{jwk}, cfg.PublishedKeys...)}
	d := DefaultPaths()
	s.paths = cfg.Paths
	for _, f := range []struct {
		dst *string
		def string
	}{
		{&s.paths.JWKS, d.JWKS}, {&s.paths.Token, d.Token}, {&s.paths.Refresh, d.Refresh}, {&s.paths.Subagent, d.Subagent},
	} {
		if *f.dst == "" {
			*f.dst = f.def
		}
	}
	s.domain = cfg.Domain
	if s.domain == "" {
		u, err := url.Parse(cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("agentprovider: Config.Issuer: %w", err)
		}
		s.domain = u.Hostname()
	}
	if _, err := aauth.ParseAgentIdentifier("aauth:probe@" + s.domain); err != nil {
		return nil, fmt.Errorf("agentprovider: agent identifier domain: %w", err)
	}
	if s.replay == nil {
		s.replay = NewMemoryReplayCache()
	}
	s.mux = http.NewServeMux()
	s.Register(s.mux)
	return s, nil
}

// ServeHTTP serves the provider routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Register adds the provider routes to mux. The issuance endpoints are
// registered only with a Registrar.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/"+aauth.WellKnownAgent, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Metadata())
	})
	mux.HandleFunc("GET "+s.paths.JWKS, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeJSON(w, http.StatusOK, s.jwks)
	})
	if s.cfg.Registrar != nil {
		mux.HandleFunc("POST "+s.paths.Token, s.serveIssue)
		mux.HandleFunc("POST "+s.paths.Refresh, s.serveRefresh)
		mux.HandleFunc("POST "+s.paths.Subagent, s.serveSubagent)
	}
}

// Issuer returns the provider's issuer.
func (s *Server) Issuer() string { return s.cfg.Issuer }

// JWKS returns the provider's published key set.
func (s *Server) JWKS() aauth.JWKS { return s.jwks }

// Signer returns the provider's server signer, for revocations (§11.3.2).
func (s *Server) Signer() aauth.ServerSigner {
	return aauth.ServerSigner{Issuer: s.cfg.Issuer, DWK: aauth.WellKnownAgent, Kid: s.kid, Key: s.cfg.Key}
}

// Metadata returns the provider's metadata document (draft -11 §11.2.1).
func (s *Server) Metadata() aauth.AgentProviderMetadata {
	md := s.cfg.Metadata
	md.Issuer = s.cfg.Issuer
	md.JWKSURI = strings.TrimSuffix(s.cfg.Issuer, "/") + s.paths.JWKS
	return md
}

// Resolver is a KeyResolver for this provider's own tokens, for verifiers
// collocated with it.
func (s *Server) Resolver() aauth.KeyResolver { return aauth.StaticResolver{s.cfg.Issuer: s.jwks} }

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

// AgentTokenParams describes an agent token to issue.
type AgentTokenParams struct {
	// Name is the agent identifier's local part; the domain is the
	// provider's. A sub-agent's name carries "+discriminator".
	Name string
	// Key is the agent's public key (cnf.jwk); never the provider's.
	Key aauth.JWK
	// PS is the ps claim; ParentAgent marks a sub-agent token.
	PS          string
	ParentAgent string
	// TTL is the lifetime (default Config.TokenTTL, at most 24 hours);
	// NotAfter, when set, caps exp (a sub-agent's parent token).
	TTL      time.Duration
	NotAfter time.Time
}

// IssueAgentToken issues an agent token for an arbitrary public key the
// hosting application has authorized — for example a key bound to its own
// session record — signed by the provider's key (draft -11 §5.3). It
// reports the token to Config.OnIssue.
func (s *Server) IssueAgentToken(ctx context.Context, p AgentTokenParams) (string, *aauth.AgentClaims, error) {
	id, err := aauth.ParseAgentIdentifier("aauth:" + p.Name + "@" + s.domain)
	if err != nil {
		return "", nil, err
	}
	if err := p.Key.Validate(); err != nil {
		return "", nil, fmt.Errorf("agentprovider: agent key: %w", err)
	}
	if _, err := p.Key.PublicKey(); err != nil {
		return "", nil, fmt.Errorf("agentprovider: agent key: %w", err)
	}
	if s.jwks.Keys[0].Thumbprint() == p.Key.Thumbprint() {
		return "", nil, errors.New("agentprovider: an agent key must not be the provider's signing key")
	}
	ttl := firstPositive(p.TTL, s.cfg.TokenTTL, time.Hour)
	if ttl > aauth.MaxAgentTokenLifetime {
		ttl = aauth.MaxAgentTokenLifetime
	}
	now := s.now()
	exp := now.Add(ttl)
	if !p.NotAfter.IsZero() && p.NotAfter.Before(exp) {
		exp = p.NotAfter
	}
	if !exp.After(now) {
		return "", nil, fmt.Errorf("%w: the token's exp bound is not in the future", aauth.ErrExpired)
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", nil, err
	}
	key := p.Key
	key.Kid, key.Use = "", ""
	claims := aauth.AgentClaims{
		DWK: aauth.WellKnownAgent, PS: p.PS, ParentAgent: p.ParentAgent, Cnf: aauth.Cnf{JWK: &key},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: s.cfg.Issuer, Subject: id.String(), ID: base64.RawURLEncoding.EncodeToString(jti),
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok, err := aauth.MintAgentToken(claims, s.cfg.Key, s.kid)
	if err != nil {
		return "", nil, err
	}
	if s.cfg.OnIssue != nil {
		s.cfg.OnIssue(ctx, IssuedToken{Token: tok, Claims: &claims})
	}
	return tok, &claims, nil
}

// TokenResponse is the body of a successful issuance, refresh, or
// sub-agent response.
type TokenResponse struct {
	AgentToken string `json:"agent_token"`
	ExpiresIn  int64  `json:"expires_in"`
}

// signatureOptions require content-digest and content-type on bodies: an
// issuance binds the public key the body carries (bootstrap §8.1).
func (s *Server) signatureOptions() aauth.RequestVerifyOptions {
	now := s.now()
	return aauth.RequestVerifyOptions{Window: s.cfg.SignatureWindow, RequireBodyCoverage: true, Now: func() time.Time { return now }}
}

// serveIssue issues a token for the key an hwk-signed request presents:
// enrollment, or single-key refresh (bootstrap §8.2).
func (s *Server) serveIssue(w http.ResponseWriter, r *http.Request) {
	sk, body, ok := s.begin(w, r, SchemeHWK)
	if !ok {
		return
	}
	key, err := verifyHWK(r, sk, s.signatureOptions())
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	att, ok := s.attest(w, r, body, key)
	if !ok {
		return
	}
	if !s.limit(w, r, "issue:"+key.Thumbprint()) {
		return
	}
	reg, err := s.cfg.Registrar.AuthorizeIssue(r.Context(), r, &IssueRequest{Key: key, Body: body, Attestation: att})
	s.finish(w, r, reg, err, key)
}

// serveRefresh is the two-key refresh (bootstrap §8.1): a naming JWT
// signed by the durable key delegates to the ephemeral key that signed the
// request; the new token binds the ephemeral key.
func (s *Server) serveRefresh(w http.ResponseWriter, r *http.Request) {
	sk, body, ok := s.begin(w, r, SchemeJKTJWT)
	if !ok {
		return
	}
	d, err := verifyJKTJWT(r, sk, s.signatureOptions(), s.now())
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	if d.jti == "" {
		aauth.WriteSignatureError(w, aauth.SignatureError{Code: aauth.SigErrInvalidJWT}, "the naming JWT needs a jti for replay protection")
		return
	}
	if !s.limit(w, r, "refresh:"+JKTURN(d.durable)) {
		return
	}
	fresh, err := s.replay.Remember(r.Context(), JKTURN(d.durable)+"|"+d.jti, d.exp)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !fresh {
		aauth.WriteSignatureError(w, aauth.SignatureError{Code: aauth.SigErrInvalidJWT}, errReplay.Error())
		return
	}
	att, ok := s.attest(w, r, body, d.durable)
	if !ok {
		return
	}
	reg, err := s.cfg.Registrar.AuthorizeRefresh(r.Context(), &RefreshRequest{
		Durable: d.durable, DurableID: JKTURN(d.durable), Ephemeral: d.ephemeral, Body: body, Attestation: att,
	})
	s.finish(w, r, reg, err, d.ephemeral)
}

// subagentBody is the body of a sub-agent request (bootstrap §9.2; the
// member names are this provider's).
type subagentBody struct {
	JWK           *aauth.JWK `json:"jwk"`
	Discriminator string     `json:"discriminator,omitempty"`
}

// serveSubagent issues a sub-agent token to a parent (bootstrap §9.2):
// the parent signs with its own agent token from this provider; the token
// has the parent's iss and ps, sub the parent's name plus a
// discriminator, parent_agent naming the parent, cnf the sub-agent's key,
// and exp no later than the parent's. A sub-agent may not have sub-agents.
func (s *Server) serveSubagent(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.begin(w, r, aauth.SchemeJWT); !ok {
		return
	}
	parent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{
		Resolver: s.Resolver(), Signature: s.signatureOptions(),
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	if parent.Issuer != s.cfg.Issuer {
		aauth.WriteSignatureError(w, aauth.SignatureError{Code: aauth.SigErrInvalidJWT}, "the parent's agent token is not from this provider")
		return
	}
	if parent.IsSubAgent() {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.PollErrDenied, "a sub-agent may not have sub-agents (§10.2.2)")
		return
	}
	var body subagentBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.JWK == nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "the body must carry the sub-agent's jwk")
		return
	}
	if _, err := body.JWK.PublicKey(); err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "jwk: "+err.Error())
		return
	}
	if body.JWK.Thumbprint() == parent.Cnf.JWK.Thumbprint() {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "a sub-agent holds its own key, never its parent's")
		return
	}
	if !s.limit(w, r, "subagent:"+parent.Subject) {
		return
	}
	g, err := s.cfg.Registrar.AuthorizeSubagent(r.Context(), &SubagentRequest{Parent: parent, Key: *body.JWK, Discriminator: body.Discriminator})
	if err != nil {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.PollErrDenied, err.Error())
		return
	}
	disc := body.Discriminator
	if g.Discriminator != "" {
		disc = g.Discriminator
	}
	if disc == "" {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			s.serverError(w, r, err)
			return
		}
		disc = base64.RawURLEncoding.EncodeToString(b)
	}
	pid, err := aauth.ParseAgentIdentifier(parent.Subject)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sid, err := pid.SubAgent(disc)
	if err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(sid.String(), "aauth:"), "@"+pid.Domain)
	tok, claims, err := s.IssueAgentToken(r.Context(), AgentTokenParams{
		Name: name, Key: *body.JWK, PS: parent.PS, ParentAgent: parent.Subject, TTL: g.TTL, NotAfter: parent.ExpiresAt.Time,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{AgentToken: tok, ExpiresIn: int64(claims.ExpiresAt.Sub(s.now()) / time.Second)})
}

// begin bounds and reads the body (restoring it for signature
// verification) and requires the expected Signature-Key scheme.
func (s *Server) begin(w http.ResponseWriter, r *http.Request, scheme string) (aauth.SignatureKey, []byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
		return aauth.SignatureKey{}, nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sk, err := aauth.ParseSignatureKeyMember(r, aauth.DefaultSignatureLabel)
	if err == nil && sk.Scheme != scheme {
		err = &aauth.UnsupportedSchemeError{Scheme: sk.Scheme, Accepted: []string{scheme}}
	}
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return aauth.SignatureKey{}, nil, false
	}
	return sk, body, true
}

// attest verifies attestation evidence in the body's "attestation" member,
// when present.
func (s *Server) attest(w http.ResponseWriter, r *http.Request, body []byte, key aauth.JWK) (*Attestation, bool) {
	var b struct {
		Attestation json.RawMessage `json:"attestation"`
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &b); err != nil {
			aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
			return nil, false
		}
	}
	if len(b.Attestation) == 0 {
		return nil, true
	}
	if s.cfg.Attestation == nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "this provider does not verify attestation")
		return nil, false
	}
	att, err := s.cfg.Attestation.VerifyAttestation(r.Context(), b.Attestation, key)
	if err != nil {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.PollErrDenied, "attestation: "+err.Error())
		return nil, false
	}
	return att, true
}

// finish issues the token a Registrar authorized for key.
func (s *Server) finish(w http.ResponseWriter, r *http.Request, reg *Registration, err error, key aauth.JWK) {
	if err != nil {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.PollErrDenied, err.Error())
		return
	}
	tok, claims, err := s.IssueAgentToken(r.Context(), AgentTokenParams{Name: reg.Name, Key: key, PS: reg.PS, TTL: reg.TTL})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{AgentToken: tok, ExpiresIn: int64(claims.ExpiresAt.Sub(s.now()) / time.Second)})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger().ErrorContext(r.Context(), "agentprovider", "error", err)
	aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
}

// RevokeAgentToken revokes an agent token the provider issued at the
// agent's person server (draft -11 §11.12.2: agent tokens are revoked at
// the PS only), discovering its revocation endpoint and signing as the
// provider. The PS cascades to the person and auth tokens it issued to the
// agent.
func (s *Server) RevokeAgentToken(ctx context.Context, ps, jti string, exp time.Time) error {
	ep, err := aauth.RevocationEndpoint(ctx, s.cfg.HTTPClient, ps, aauth.WellKnownPerson)
	if err != nil {
		return err
	}
	c := aauth.RevocationClient{Signer: s.Signer(), HTTPClient: s.cfg.HTTPClient}
	_, err = c.Revoke(ctx, ep, aauth.RevocationRequest{JTI: jti, Exp: exp.Unix()})
	return err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(v)
}

func firstPositive(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}

// limit consults Config.Limiter, answering 429 rate_limited when refused.
func (s *Server) limit(w http.ResponseWriter, r *http.Request, key string) bool {
	if s.cfg.Limiter == nil {
		return true
	}
	ok, wait := s.cfg.Limiter.Allow(r.Context(), key)
	if !ok {
		w.Header().Set(aauth.HeaderRetryAfter, strconv.Itoa(int(max((wait+time.Second-1)/time.Second, 1))))
		aauth.WriteProblem(w, http.StatusTooManyRequests, aauth.ErrCodeRateLimited, "")
	}
	return ok
}
