package aauth

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Agent is a self-hosted agent: it acts as its own agent provider and
// self-issues agent tokens signed by its published key
// (draft-hardt-aauth-bootstrap-02 §4.3). One key serves both as the AP
// signing key and as the cnf.jwk HTTP-signing key.
type Agent struct {
	// ID is the agent identifier (the token's sub), stable across rotations.
	ID AgentIdentifier
	// Issuer is the agent provider URL. For a self-hosted agent this is a
	// domain the operator controls, publishing /.well-known/aauth-agent.json.
	// Empty for purely local deployments verified via SelfSignedResolver.
	Issuer string
	// PS is the agent's Person Server URL (optional ps claim).
	PS string
	// TokenTTL bounds minted tokens; capped at 24h per draft -11 §5.3.1.
	TokenTTL time.Duration

	// Key is the agent's signing key. It signs both self-issued agent
	// tokens and HTTP messages; its public half appears in cnf.jwk. Any
	// supported crypto.Signer works (Ed25519 or P-256; see [GenerateKey]),
	// including keys held in a platform keystore.
	Key crypto.Signer

	// keyAlg selects the algorithm NewAgent generates a key for.
	keyAlg string
	// tokenSource, when set, supplies agent tokens issued by another party
	// (a sub-agent's parent, a hosted agent provider) instead of
	// self-issuing them.
	tokenSource func() (string, error)
}

// NewAgent creates an agent for the given identifier. Unless [WithKey]
// supplies a key, it generates a fresh one — Ed25519 by default, or the
// algorithm chosen with [WithKeyAlgorithm].
func NewAgent(id AgentIdentifier, opts ...AgentOption) (*Agent, error) {
	a := &Agent{ID: id, TokenTTL: time.Hour, keyAlg: AlgEd25519}
	for _, o := range opts {
		o(a)
	}
	if a.Key == nil {
		key, err := GenerateKey(a.keyAlg)
		if err != nil {
			return nil, err
		}
		a.Key = key
	}
	if _, err := AlgForPublicKey(a.Key.Public()); err != nil {
		return nil, err
	}
	return a, nil
}

// AgentOption configures NewAgent.
type AgentOption func(*Agent)

// WithIssuer sets the agent-provider URL (self-hosted domain).
func WithIssuer(iss string) AgentOption { return func(a *Agent) { a.Issuer = iss } }

// WithPersonServer sets the ps claim.
func WithPersonServer(ps string) AgentOption { return func(a *Agent) { a.PS = ps } }

// WithKey uses an existing signing key instead of generating one: an
// ed25519.PrivateKey, a P-256 *ecdsa.PrivateKey, or any crypto.Signer with
// such a public key (for example a hardware-backed key).
func WithKey(key crypto.Signer) AgentOption {
	return func(a *Agent) { a.Key = key }
}

// WithKeyAlgorithm selects the algorithm of the key NewAgent generates
// ([AlgEd25519], the default, or [AlgES256]). It has no effect with WithKey.
func WithKeyAlgorithm(alg string) AgentOption { return func(a *Agent) { a.keyAlg = alg } }

// WithTokenSource makes the agent present tokens issued elsewhere instead
// of self-issuing them: fn returns a current agent token whose cnf.jwk is
// the agent's Key — for example one a hosted agent provider issued, or a
// sub-agent token handed to a worker process (bootstrap §9). fn is called
// once per token the agent presents and should cache.
func WithTokenSource(fn func() (string, error)) AgentOption {
	return func(a *Agent) { a.tokenSource = fn }
}

// WithTokenTTL overrides the minted-token lifetime (capped at 24h).
func WithTokenTTL(d time.Duration) AgentOption { return func(a *Agent) { a.TokenTTL = d } }

// Alg returns the fully-specified algorithm of the agent's key.
func (a *Agent) Alg() (string, error) {
	if a.Key == nil {
		return "", fmt.Errorf("%w: Agent.Key is nil", ErrInvalidKey)
	}
	return AlgForPublicKey(a.Key.Public())
}

// JWK returns the agent's public key with Kid = RFC 7638 thumbprint.
//
// It panics if Key is nil or of an unsupported type — a programming error
// that NewAgent rules out.
func (a *Agent) JWK() JWK {
	if a.Key == nil {
		panic("aauth: Agent.Key is nil")
	}
	j, err := NewJWK(a.Key.Public())
	if err != nil {
		panic(fmt.Sprintf("aauth: Agent.Key: %v", err))
	}
	return j
}

// Thumbprint is the agent key's RFC 7638 thumbprint.
func (a *Agent) Thumbprint() string { return a.JWK().Thumbprint() }

// JWKS returns the one-key set a self-hosted agent publishes at its jwks_uri.
func (a *Agent) JWKS() JWKS { return JWKS{Keys: []JWK{a.JWK()}} }

// MintToken returns a fresh agent token for the agent: from its token
// source ([WithTokenSource], [Agent.NewSubAgent]) when it has one, else
// self-issued — an aa-agent+jwt with iss, dwk, sub, jti, cnf.jwk, iat, exp
// (+ ps when configured), signed by Key.
func (a *Agent) MintToken() (string, error) {
	if a.tokenSource != nil {
		return a.tokenSource()
	}
	return a.mint(a.ID, "", a.JWK(), time.Now())
}

// IssueSubAgentToken issues, as this agent's own (self-hosted) agent
// provider, an agent token for a sub-agent that holds its own key pub
// (draft -11 §10.2.1; bootstrap §9.1): sub is this agent's identifier with
// "+discriminator", parent_agent names this agent, iss and ps are this
// agent's, cnf.jwk is pub, and exp does not exceed the agent's own token
// lifetime. The sub-agent signs its requests with its own key; a sub-agent
// never shares its parent's. A sub-agent cannot have sub-agents
// (§10.2.2), and an agent whose tokens come from elsewhere cannot issue
// them — its provider does.
func (a *Agent) IssueSubAgentToken(discriminator string, pub crypto.PublicKey) (string, error) {
	switch {
	case a.ID.IsSubAgent():
		return "", fmt.Errorf("aauth: sub-agent %s cannot have sub-agents (§10.2.2)", a.ID)
	case a.tokenSource != nil:
		return "", errors.New("aauth: an agent whose tokens are issued elsewhere cannot issue sub-agent tokens; its agent provider does")
	}
	sub, err := a.ID.SubAgent(discriminator)
	if err != nil {
		return "", err
	}
	jwk, err := NewJWK(pub)
	if err != nil {
		return "", fmt.Errorf("aauth: sub-agent key: %w", err)
	}
	return a.mint(sub, a.ID.String(), jwk, time.Now())
}

// NewSubAgent creates a sub-agent of this self-hosted agent (draft -11
// §10.2): its identifier is this one's with "+discriminator", it holds its
// own key (generated, or supplied with [WithKey] / [WithKeyAlgorithm]),
// and its tokens are issued on demand by this agent with
// [Agent.IssueSubAgentToken]. Only the issuing process needs this agent's
// key; a sub-agent in another process receives its token out of band and
// uses [WithTokenSource].
//
// A sub-agent MUST NOT call the PS itself. Its parent obtains its person
// and auth tokens (§10.2.3): give the sub-agent a [Transport] whose PS is
// the parent's [PSClient] — NewTransport(sub, parentPS) — and the
// transport sends the sub-agent's token as subagent_token in requests the
// parent signs.
func (a *Agent) NewSubAgent(discriminator string, opts ...AgentOption) (*Agent, error) {
	id, err := a.ID.SubAgent(discriminator)
	if err != nil {
		return nil, err
	}
	sub, err := NewAgent(id, append([]AgentOption{WithIssuer(a.Issuer), WithPersonServer(a.PS), WithTokenTTL(a.TokenTTL)}, opts...)...)
	if err != nil {
		return nil, err
	}
	if _, err := a.IssueSubAgentToken(discriminator, sub.Key.Public()); err != nil {
		return nil, err
	}
	pub := sub.Key.Public()
	sub.tokenSource = func() (string, error) { return a.IssueSubAgentToken(discriminator, pub) }
	return sub, nil
}

// mint signs an agent token for sub, binding jwk, with parent_agent set
// for a sub-agent.
func (a *Agent) mint(sub AgentIdentifier, parent string, jwk JWK, now time.Time) (string, error) {
	ttl := a.TokenTTL
	if max := time.Duration(MaxAgentTokenTTLSeconds) * time.Second; ttl <= 0 || ttl > max {
		ttl = max
	}
	if _, err := a.Alg(); err != nil {
		return "", err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := AgentClaims{
		DWK:         WellKnownAgent,
		PS:          a.PS,
		ParentAgent: parent,
		Cnf:         Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.Issuer,
			Subject:   sub.String(),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return MintAgentToken(claims, a.Key, a.JWK().Kid)
}

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("aauth: jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
