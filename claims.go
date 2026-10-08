package aauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Common JWT claim rules (draft -11 §11.5). Every AAuth token — agent,
// person, resource, and auth — shares the header (alg, typ, kid) and the
// claims iss, dwk, jti, iat, exp, and (except resource tokens) cnf.
// Verification (§11.5.2) checks typ, dwk, the signature under the issuer's
// key, exp against the verifier's own clock with no skew tolerance, and that
// iss is a server identifier (§11.1.1). iat is REQUIRED but is not a
// validity check; a verifier MAY refuse an iat further ahead of its clock
// than its signature validity window, answering clock_skew.

// Token lifetime limits (draft -11 §5.3.1, §6.7.1, §7.1.2, §9.4.1).
const (
	// MaxAgentTokenLifetime is the lifetime an agent token SHOULD NOT
	// exceed (§5.3.1).
	MaxAgentTokenLifetime = 24 * time.Hour
	// MaxPersonTokenLifetime is the lifetime a person token MUST NOT
	// exceed (§7.1.2).
	MaxPersonTokenLifetime = time.Hour
	// MaxAuthTokenLifetime is the lifetime an auth token MUST NOT exceed
	// (§9.4.1).
	MaxAuthTokenLifetime = time.Hour
	// MaxResourceTokenLifetime is the lifetime a resource token SHOULD NOT
	// exceed (§6.7.1).
	MaxResourceTokenLifetime = 5 * time.Minute
)

// BoundedExpiry computes the exp of a token issued at now (draft -11
// §7.1.2, §9.4.1): now+ttl, where a ttl that is zero, negative, or larger
// than max becomes max, and never later than any non-zero bound. Pass as
// bounds the exp of the agent token presented when the token was requested,
// of the presented_token and upstream_token, and a mission's expires_at, as
// the token type requires. The result is truncated to whole seconds (the
// JWT NumericDate precision). An error wrapping [ErrExpired] means a bound
// is not after now, so no valid token can be issued.
func BoundedExpiry(now time.Time, ttl, max time.Duration, bounds ...time.Time) (time.Time, error) {
	if ttl <= 0 || ttl > max {
		ttl = max
	}
	exp := now.Add(ttl)
	for _, b := range bounds {
		if !b.IsZero() && b.Before(exp) {
			exp = b
		}
	}
	exp = exp.Truncate(time.Second)
	if !exp.After(now) {
		return time.Time{}, fmt.Errorf("%w: a lifetime bound (%s) is not after now", ErrExpired, exp.UTC().Format(time.RFC3339))
	}
	return exp, nil
}

// TokenVerifyOptions tunes verification of tokens issued by servers —
// person, resource, and auth tokens (draft -11 §11.5.2).
type TokenVerifyOptions struct {
	// Resolver locates the issuer's token-signing key. Required.
	Resolver KeyResolver
	// Signature tunes HTTP message-signature verification in the
	// VerifyAndExtract helpers. Its clock (Now) and validity window
	// (Window) also bound how far a token's iat may be ahead of the
	// verifier's clock before it is refused as clock skew (§11.5.2).
	Signature RequestVerifyOptions
	// InsecureSkipIdentifierCheck accepts an iss (and ps) that is not a
	// server identifier (§11.1.1: https, host only, lowercase), for
	// development and tests against local servers. Never set it in
	// production.
	InsecureSkipIdentifierCheck bool
}

func (o TokenVerifyOptions) checkServerIdentifier(claim, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s", ErrMissingClaim, claim)
	}
	if o.InsecureSkipIdentifierCheck {
		return nil
	}
	if err := ValidateServerIdentifier(v); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidToken, claim, err)
	}
	return nil
}

// aauthClaims is implemented by the claim structs of every AAuth token
// type, exposing what the common verification needs.
type aauthClaims interface {
	jwt.Claims
	registered() *jwt.RegisteredClaims
	wellKnown() string
	confirmation() *JWK
}

func (c *AgentClaims) registered() *jwt.RegisteredClaims { return &c.RegisteredClaims }
func (c *AgentClaims) wellKnown() string                 { return c.DWK }
func (c *AgentClaims) confirmation() *JWK                { return c.Cnf.JWK }

// jwtCheck is the common verification of one token type (draft -11
// §11.5.2), short of the exp check: callers finish with [checkExpiry] after
// their type-specific checks, so that a token failing only on exp is
// reported as expired (§11.9.3: expired_* applies "when only exp fails").
type jwtCheck struct {
	typ  string   // expected typ header
	dwks []string // accepted dwk values; empty skips the check
	// maxLifetime is a MUST ceiling on exp − iat (person and auth
	// tokens); zero means none.
	maxLifetime time.Duration
	// issuer, when non-nil, validates iss before any key is resolved.
	issuer   func(iss string) error
	resolver KeyResolver
	clock    RequestVerifyOptions
}

// verify decodes and verifies token into dst.
func (c jwtCheck) verify(ctx context.Context, token string, dst aauthClaims) error {
	if c.resolver == nil {
		return fmt.Errorf("aauth: a KeyResolver is required to verify %s", c.typ)
	}
	// First pass, unverified: read typ, alg, kid, dwk, iss, and cnf to
	// select the key.
	utok, _, err := newJWTParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, dst)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if typ, _ := utok.Header["typ"].(string); typ != c.typ {
		return fmt.Errorf("%w: typ=%q want %q", ErrWrongTokenType, utok.Header["typ"], c.typ)
	}
	if err := checkJWSHeaderAlg(utok); err != nil {
		return err
	}
	if len(c.dwks) > 0 && !contains(c.dwks, dst.wellKnown()) {
		return fmt.Errorf("%w: dwk %q, want one of %q", ErrInvalidToken, dst.wellKnown(), c.dwks)
	}
	rc := dst.registered()
	if c.issuer != nil {
		if err := c.issuer(rc.Issuer); err != nil {
			return err
		}
	}
	kid, _ := utok.Header["kid"].(string)
	tok, err := parseSigned(ctx, token, dst, c.resolver, rc.Issuer, dst.wellKnown(), kid, dst.confirmation())
	if err != nil {
		return classifyJWTError(err)
	}
	if !tok.Valid {
		return ErrInvalidToken
	}
	rc = dst.registered()
	if rc.ID == "" {
		// jti names the token for revocation and for presented_jti
		// (§11.5, §11.12); a token without one cannot be revoked.
		return fmt.Errorf("%w: jti", ErrMissingClaim)
	}
	if rc.IssuedAt == nil {
		return fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	if rc.ExpiresAt == nil {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	now := c.clock.now()
	if ahead := rc.IssuedAt.Sub(now); ahead > c.clock.window() {
		return fmt.Errorf("%w: iat is %s ahead of the verifier's clock", ErrClockSkew, ahead.Round(time.Second))
	}
	if c.maxLifetime > 0 && rc.ExpiresAt.Sub(rc.IssuedAt.Time) > c.maxLifetime {
		return fmt.Errorf("%w: lifetime (exp - iat) exceeds %s", ErrInvalidToken, c.maxLifetime)
	}
	if rc.NotBefore != nil && now.Before(rc.NotBefore.Time) {
		return fmt.Errorf("%w: nbf is in the future", ErrInvalidToken)
	}
	return nil
}

// checkExpiry is the final verification step (draft -11 §11.5.2 step 3):
// exp MUST be in the future, judged by the verifier's own clock, with no
// tolerance for clock skew.
func checkExpiry(rc *jwt.RegisteredClaims, clock RequestVerifyOptions) error {
	if rc.ExpiresAt == nil {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if !clock.now().Before(rc.ExpiresAt.Time) {
		return fmt.Errorf("%w: exp %s", ErrExpired, rc.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkAudience requires a single-valued aud equal to want.
func checkAudience(kind string, aud jwt.ClaimStrings, want string) error {
	if len(aud) != 1 || aud[0] != want {
		return fmt.Errorf("%w: %s aud %v, want %q", ErrInvalidToken, kind, []string(aud), want)
	}
	return nil
}

// timeOf returns d's time, or the zero time for an absent claim.
func timeOf(d *jwt.NumericDate) time.Time {
	if d == nil {
		return time.Time{}
	}
	return d.Time
}

// checkCnf applies the cnf.jwk structural checks of draft -11 §9.4.3.2
// step 3: cnf.jwk is REQUIRED, and a JWK missing kty or the members its key
// type requires (crv and x for OKP; crv, x, and y for EC) is structurally
// incomplete ([ErrMissingClaim]) and rejected before key decoding. A JWK
// that does not carry a fully-specified alg agreeing with kty/crv, or that
// does not decode to a supported public key, is invalid key material.
func checkCnf(j *JWK) error {
	if j == nil {
		return fmt.Errorf("%w: cnf.jwk", ErrMissingClaim)
	}
	var missing []string
	switch j.Kty {
	case "":
		missing = append(missing, "kty")
	case "OKP":
		if j.Crv == "" {
			missing = append(missing, "crv")
		}
		if j.X == "" {
			missing = append(missing, "x")
		}
	case "EC":
		if j.Crv == "" {
			missing = append(missing, "crv")
		}
		if j.X == "" {
			missing = append(missing, "x")
		}
		if j.Y == "" {
			missing = append(missing, "y")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: cnf.jwk is missing %v", ErrMissingClaim, missing)
	}
	if _, err := j.PublicKey(); err != nil {
		return fmt.Errorf("cnf.jwk: %w", err)
	}
	return nil
}
