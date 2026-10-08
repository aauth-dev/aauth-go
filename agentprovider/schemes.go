package agentprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/golang-jwt/jwt/v5"
)

// Signature-Key schemes an agent provider accepts besides jwt
// (signature-key §3.4, §3.5; bootstrap §8): hwk carries a public key
// inline, for enrollment and single-key refresh; jkt-jwt carries a JWT
// signed by a durable (enclave) key that delegates to an ephemeral key,
// for two-key refresh.
const (
	SchemeHWK    = "hwk"
	SchemeJKTJWT = "jkt-jwt"
	// TypJKTS256 is the typ of a jkt-jwt naming JWT whose thumbprint is
	// SHA-256; its iss is urn:jkt:sha-256:<thumbprint>.
	TypJKTS256   = "jkt-s256+jwt"
	jktURNPrefix = "urn:jkt:sha-256:"
)

// JKTURN is the JWK Thumbprint URI of a key (signature-key §3.5):
// urn:jkt:sha-256:<RFC 7638 thumbprint>. It is the stable, pseudonymous
// identity of a durable key.
func JKTURN(j aauth.JWK) string { return jktURNPrefix + j.Thumbprint() }

// AttachHWK sets Signature-Key to the hwk scheme carrying pub inline
// (signature-key §3.4): kty, crv, x (and y), and the fully-specified alg;
// no kid.
func AttachHWK(req *http.Request, pub crypto.PublicKey) error {
	j, err := aauth.NewJWK(pub)
	if err != nil {
		return err
	}
	v := aauth.DefaultSignatureLabel + "=hwk;kty=" + sfString(j.Kty) + ";crv=" + sfString(j.Crv) + ";x=" + sfString(j.X)
	if j.Y != "" {
		v += ";y=" + sfString(j.Y)
	}
	req.Header.Set(aauth.HeaderSignatureKey, v+";alg="+sfString(j.Alg))
	return nil
}

// SignHWK signs req with key under the hwk scheme: the request proves
// possession of the key it presents.
func SignHWK(req *http.Request, key crypto.Signer) error {
	if err := AttachHWK(req, key.Public()); err != nil {
		return err
	}
	return aauth.SignRequest(req, key, "")
}

// NewNamingJWT creates the jkt-jwt naming JWT of a two-key refresh
// (bootstrap §8.1; signature-key §3.5): signed by the durable key, whose
// public JWK is in the header and whose thumbprint URI is iss, delegating
// to the ephemeral key in cnf.jwk, with iat, exp (now + ttl), and a jti
// for replay protection. durable may be any crypto.Signer — typically a
// hardware-backed key.
func NewNamingJWT(durable crypto.Signer, ephemeral crypto.PublicKey, ttl time.Duration) (string, error) {
	dj, err := aauth.NewJWK(durable.Public())
	if err != nil {
		return "", err
	}
	ej, err := aauth.NewJWK(ephemeral)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	dj.Kid, dj.Use, ej.Kid, ej.Use = "", "", "", ""
	header := map[string]any{"typ": TypJKTS256, "alg": dj.Alg, "jwk": dj}
	payload := map[string]any{
		"iss": JKTURN(dj), "iat": now.Unix(), "exp": now.Add(ttl).Unix(),
		"cnf": map[string]any{"jwk": ej}, "jti": base64.RawURLEncoding.EncodeToString(jti),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := signJOSE(durable, dj.Alg, []byte(signing))
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignJKTJWT signs req with the ephemeral key under the jkt-jwt scheme,
// presenting namingJWT (bootstrap §8.1 step 3).
func SignJKTJWT(req *http.Request, namingJWT string, ephemeral crypto.Signer) error {
	req.Header.Set(aauth.HeaderSignatureKey, aauth.DefaultSignatureLabel+"=jkt-jwt;jwt="+sfString(namingJWT))
	return aauth.SignRequest(req, ephemeral, "")
}

// verifyHWK authenticates a request signed under the hwk scheme and
// returns the key it presented.
func verifyHWK(req *http.Request, sk aauth.SignatureKey, opts aauth.RequestVerifyOptions) (aauth.JWK, error) {
	if _, ok := sk.Params["kid"]; ok {
		return aauth.JWK{}, fmt.Errorf("%w: the hwk scheme does not take kid", aauth.ErrBadSigKey)
	}
	j := aauth.JWK{Kty: sk.Params["kty"], Crv: sk.Params["crv"], X: sk.Params["x"], Y: sk.Params["y"], Alg: sk.Params["alg"]}
	pub, err := j.PublicKey()
	if err != nil {
		return aauth.JWK{}, err
	}
	if err := aauth.VerifyRequestWithOptions(req, pub, opts); err != nil {
		return aauth.JWK{}, err
	}
	return j, nil
}

// namingClaims is the payload of a jkt-jwt naming JWT.
type namingClaims struct {
	Cnf aauth.Cnf `json:"cnf"`
	jwt.RegisteredClaims
}

// delegation is a verified jkt-jwt: the durable key and the ephemeral key
// it delegated to.
type delegation struct {
	durable   aauth.JWK
	ephemeral aauth.JWK
	jti       string
	exp       time.Time
}

// verifyJKTJWT authenticates a request signed under the jkt-jwt scheme
// (signature-key §3.5 verification procedure): the typ, the header jwk,
// iss equal to its thumbprint URI, the JWT signature under it, iat and exp
// (iat no further ahead than the signature window), the ephemeral key in
// cnf.jwk, and the HTTP signature under that key.
func verifyJKTJWT(req *http.Request, sk aauth.SignatureKey, opts aauth.RequestVerifyOptions, now time.Time) (*delegation, error) {
	tok := sk.Params["jwt"]
	if tok == "" {
		return nil, fmt.Errorf("%w: jkt-jwt scheme without a jwt parameter", aauth.ErrBadSigKey)
	}
	var claims namingClaims
	parser := jwt.NewParser(jwt.WithValidMethods(aauth.AcceptedSignatureAlgs()), jwt.WithoutClaimsValidation())
	var durable aauth.JWK
	t, err := parser.ParseWithClaims(tok, &claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != TypJKTS256 {
			return nil, fmt.Errorf("%w: typ %q", aauth.ErrWrongTokenType, t.Header["typ"])
		}
		raw, err := json.Marshal(t.Header["jwk"])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &durable); err != nil || durable.Kty == "" {
			return nil, fmt.Errorf("%w: header jwk", aauth.ErrInvalidKey)
		}
		if alg, _ := t.Header["alg"].(string); alg != durable.Alg {
			return nil, fmt.Errorf("%w: header alg %q does not match the jwk's %q", aauth.ErrInvalidKey, alg, durable.Alg)
		}
		if t.Claims.(*namingClaims).Issuer != JKTURN(durable) {
			return nil, fmt.Errorf("%w: iss is not the header jwk's thumbprint URI", aauth.ErrInvalidToken)
		}
		return durable.PublicKey()
	})
	if err != nil {
		return nil, fmt.Errorf("%w: naming JWT: %w", aauth.ErrInvalidToken, err)
	}
	if !t.Valid || claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: naming JWT needs iat and exp", aauth.ErrMissingClaim)
	}
	window := opts.Window
	if window <= 0 {
		window = aauth.DefaultSignatureWindow
	}
	switch {
	case !now.Before(claims.ExpiresAt.Time):
		return nil, fmt.Errorf("%w: naming JWT", aauth.ErrExpired)
	case claims.IssuedAt.Sub(now) > window:
		return nil, fmt.Errorf("%w: naming JWT iat is ahead of the verifier's clock", aauth.ErrClockSkew)
	case claims.Cnf.JWK == nil:
		return nil, fmt.Errorf("%w: cnf.jwk", aauth.ErrMissingClaim)
	}
	pub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}
	if err := aauth.VerifyRequestWithOptions(req, pub, opts); err != nil {
		return nil, err
	}
	return &delegation{durable: durable, ephemeral: *claims.Cnf.JWK, jti: claims.ID, exp: claims.ExpiresAt.Time}, nil
}

// signJOSE signs msg with key as a JWS under alg (Ed25519, or ES256 with
// the fixed-length r||s encoding), so any crypto.Signer works.
func signJOSE(key crypto.Signer, alg string, msg []byte) ([]byte, error) {
	switch alg {
	case aauth.AlgEd25519:
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	case aauth.AlgES256:
		d := sha256.Sum256(msg)
		der, err := key.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &sig); err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		sig.R.FillBytes(out[:32])
		sig.S.FillBytes(out[32:])
		return out, nil
	}
	return nil, fmt.Errorf("%w: %q", aauth.ErrUnsupportedAlgorithm, alg)
}

// sfString serializes s as an RFC 9651 String.
func sfString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// ReplayCache remembers naming-JWT identifiers until they expire, so a
// captured refresh request cannot be replayed (bootstrap §8.1).
type ReplayCache interface {
	// Remember records key until exp and reports whether it was new.
	Remember(ctx context.Context, key string, exp time.Time) (bool, error)
}

// MemoryReplayCache is an in-process [ReplayCache].
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryReplayCache returns an empty MemoryReplayCache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: map[string]time.Time{}}
}

// Remember implements ReplayCache, pruning expired entries as it goes.
func (c *MemoryReplayCache) Remember(_ context.Context, key string, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.seen {
		if !now.Before(e) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[key]; ok {
		return false, nil
	}
	c.seen[key] = exp
	return true, nil
}

var errReplay = errors.New("agentprovider: naming JWT replayed")
