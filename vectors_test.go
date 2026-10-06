package aauth

// Wire-format golden vectors.
//
// Each file in testdata/vectors is a JSON document
//
//	{"description": "...", "spec": "...", "kind": "<kind>", "cases": [...]}
//
// whose cases are fixed inputs and the exact wire output this implementation
// produces for them (or the verdict it reaches on them). The vectors are
// language-neutral on purpose: keys are JWKs (private keys carry d), tokens
// and headers are the literal strings on the wire, so another implementation
// can run the same files as a conformance check.
//
// Derived values (tokens, signatures) can be regenerated after an
// intentional wire change with:
//
//	go test -run TestVectors -update
//
// Review the resulting diff: every changed byte is a wire-format change.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var updateVectors = flag.Bool("update", false, "rewrite derived values in testdata/vectors")

// vectorFile is the envelope shared by every vector file.
type vectorFile struct {
	Description string          `json:"description"`
	Spec        string          `json:"spec,omitempty"`
	Kind        string          `json:"kind"`
	Cases       json.RawMessage `json:"cases"`
}

// vectorRunner runs the cases of one kind. In update mode it returns the
// cases with derived values regenerated; otherwise its return is ignored.
type vectorRunner func(t *testing.T, cases json.RawMessage, update bool) any

var vectorRunners = map[string]vectorRunner{
	"jwk-thumbprint":   runThumbprintVectors,
	"agent-identifier": runIdentifierVectors,
	"requirement":      runRequirementVectors,
	"signature-error":  runSignatureErrorVectors,
	"signature-key":    runSignatureKeyVectors,
	"metadata":         runMetadataVectors,
	"jwt":              runJWTVectors,
	"http-signature":   runHTTPSignatureVectors,
}

func TestVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}
	for _, path := range files {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vf vectorFile
			if err := json.Unmarshal(raw, &vf); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			run, ok := vectorRunners[vf.Kind]
			if !ok {
				t.Fatalf("%s: unknown vector kind %q", path, vf.Kind)
			}
			updated := run(t, vf.Cases, *updateVectors)
			if !*updateVectors || updated == nil {
				return
			}
			cases, err := json.Marshal(updated)
			if err != nil {
				t.Fatal(err)
			}
			vf.Cases = cases
			if err := writeVectorFile(path, vf); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func writeVectorFile(path string, vf vectorFile) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vf); err != nil {
		return err
	}
	// Re-indent so nested raw cases are pretty-printed too.
	var out bytes.Buffer
	if err := json.Indent(&out, buf.Bytes(), "", "  "); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func decodeCases[T any](t *testing.T, raw json.RawMessage) []T {
	t.Helper()
	var cases []T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cases); err != nil {
		t.Fatalf("decode cases: %v", err)
	}
	return cases
}

// privateJWK is a JWK including the private member d, used only by the
// vectors to carry deterministic signing keys.
type privateJWK struct {
	JWK
	D string `json:"d"`
}

// signer returns the private key the JWK describes (Ed25519 or P-256).
func (p privateJWK) signer(t *testing.T) crypto.Signer {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(p.D)
	if err != nil {
		t.Fatalf("vector key d: %v", err)
	}
	var key crypto.Signer
	switch {
	case p.Kty == "OKP" && p.Crv == "Ed25519" && len(d) == ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(d)
	case p.Kty == "EC" && p.Crv == "P-256" && len(d) == 32:
		pub, err := decodeP256(p.X, p.Y)
		if err != nil {
			t.Fatal(err)
		}
		key = &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(d)}
	default:
		t.Fatalf("unsupported vector key kty=%s crv=%s", p.Kty, p.Crv)
	}
	// The private and public halves must agree.
	derived, err := NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if derived.Thumbprint() != p.Thumbprint() {
		t.Fatal("vector key: public members do not match d")
	}
	// Prove possession of d: sign and verify.
	alg, err := AlgForPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signJOSE(key, alg, []byte("vector"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyJOSE(key.Public(), []byte("vector"), sig); err != nil {
		t.Fatalf("vector key: d does not match public key: %v", err)
	}
	return key
}

// --- jwk-thumbprint -------------------------------------------------------

type thumbprintCase struct {
	Name       string `json:"name"`
	JWK        JWK    `json:"jwk"`
	Thumbprint string `json:"thumbprint"`
}

func runThumbprintVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[thumbprintCase](t, raw) {
		if got := c.JWK.Thumbprint(); got != c.Thumbprint {
			t.Errorf("%s: thumbprint = %s, want %s", c.Name, got, c.Thumbprint)
		}
	}
	return nil
}

// --- agent-identifier -----------------------------------------------------

type identifierCase struct {
	Input         string `json:"input"`
	Valid         bool   `json:"valid"`
	Name          string `json:"name,omitempty"`
	Discriminator string `json:"discriminator,omitempty"`
	Domain        string `json:"domain,omitempty"`
}

func runIdentifierVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[identifierCase](t, raw) {
		id, err := ParseAgentIdentifier(c.Input)
		if !c.Valid {
			if err == nil {
				t.Errorf("%q: accepted, want rejected", c.Input)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.Input, err)
			continue
		}
		want := AgentIdentifier{Name: c.Name, Discriminator: c.Discriminator, Domain: c.Domain}
		if id != want {
			t.Errorf("%q: parsed %+v, want %+v", c.Input, id, want)
		}
		if id.String() != c.Input {
			t.Errorf("%q: String() = %q", c.Input, id.String())
		}
	}
	return nil
}

// --- requirement ----------------------------------------------------------

type requirementCase struct {
	Header string      `json:"header"`
	Parsed Requirement `json:"parsed"`
	// Canonical marks a header this implementation emits byte-for-byte.
	Canonical bool `json:"canonical"`
}

func runRequirementVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[requirementCase](t, raw) {
		got, err := ParseRequirement(c.Header)
		if err != nil {
			t.Errorf("%q: %v", c.Header, err)
			continue
		}
		if got != c.Parsed {
			t.Errorf("%q: parsed %+v, want %+v", c.Header, got, c.Parsed)
		}
		if c.Canonical && got.String() != c.Header {
			t.Errorf("serialize: got %q, want %q", got.String(), c.Header)
		}
	}
	return nil
}

// --- signature-error ------------------------------------------------------

type signatureErrorCase struct {
	Header        string            `json:"header"`
	Code          string            `json:"code"`
	RequiredInput []string          `json:"required_input,omitempty"`
	Params        map[string]string `json:"params,omitempty"`
	Canonical     bool              `json:"canonical"`
}

func runSignatureErrorVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[signatureErrorCase](t, raw) {
		got, err := ParseSignatureError(c.Header)
		if err != nil {
			t.Errorf("%q: %v", c.Header, err)
			continue
		}
		if got.Code != c.Code {
			t.Errorf("%q: code = %q, want %q", c.Header, got.Code, c.Code)
		}
		if !reflect.DeepEqual(got.RequiredInput, c.RequiredInput) {
			t.Errorf("%q: required_input = %v, want %v", c.Header, got.RequiredInput, c.RequiredInput)
		}
		want := c.Params
		if want == nil {
			want = map[string]string{}
		}
		if !reflect.DeepEqual(got.Params, want) {
			t.Errorf("%q: params = %v, want %v", c.Header, got.Params, want)
		}
		if c.Canonical && got.String() != c.Header {
			t.Errorf("serialize: got %q, want %q", got.String(), c.Header)
		}
	}
	return nil
}

// --- signature-key ------------------------------------------------------

type signatureKeyCase struct {
	Header string            `json:"header"`
	Scheme string            `json:"scheme,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	// Error is the Signature-Error code for a jwt-only (agent-facing)
	// verifier; empty means the header yields an agent token.
	Error string `json:"error,omitempty"`
}

func runSignatureKeyVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[signatureKeyCase](t, raw) {
		req, err := http.NewRequest(http.MethodGet, "https://resource.example/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(HeaderSignatureKey, c.Header)
		if c.Scheme != "" {
			sk, err := ParseSignatureKeyMember(req, DefaultSignatureLabel)
			if err != nil {
				t.Errorf("%q: %v", c.Header, err)
				continue
			}
			want := c.Params
			if want == nil {
				want = map[string]string{}
			}
			if sk.Scheme != c.Scheme || !reflect.DeepEqual(sk.Params, want) {
				t.Errorf("%q: parsed %+v, want scheme %q params %v", c.Header, sk, c.Scheme, want)
			}
		}
		tok, err := ParseSignatureKey(req)
		if c.Error == "" {
			if err != nil || tok != c.Params["jwt"] {
				t.Errorf("%q: token %q, %v", c.Header, tok, err)
			}
			continue
		}
		se, ok := SignatureErrorFor(err)
		if !ok || se.Code != c.Error {
			t.Errorf("%q: err = %v (%q), want %s", c.Header, err, se.Code, c.Error)
		}
	}
	return nil
}

// --- metadata -------------------------------------------------------------

type metadataCase struct {
	Document string          `json:"document"`
	JSON     json.RawMessage `json:"json"`
}

func metadataTarget(doc string) (any, error) {
	switch doc {
	case WellKnownAgent:
		return &AgentProviderMetadata{}, nil
	case WellKnownPerson:
		return &PersonServerMetadata{}, nil
	case WellKnownResource:
		return &ResourceMetadata{}, nil
	}
	return nil, fmt.Errorf("no metadata type for %q", doc)
}

// runMetadataVectors checks that each document decodes into its Go type and
// re-encodes to the same JSON object: every published member is modeled,
// under the right name.
func runMetadataVectors(t *testing.T, raw json.RawMessage, _ bool) any {
	for _, c := range decodeCases[metadataCase](t, raw) {
		dst, err := metadataTarget(c.Document)
		if err != nil {
			t.Error(err)
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(c.JSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			t.Errorf("%s: decode: %v", c.Document, err)
			continue
		}
		out, err := json.Marshal(dst)
		if err != nil {
			t.Fatal(err)
		}
		var want, got map[string]any
		if err := json.Unmarshal(c.JSON, &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: round trip\n got %s\nwant %s", c.Document, out, c.JSON)
		}
	}
	return nil
}

// --- jwt ------------------------------------------------------------------

type jwtCase struct {
	Name       string          `json:"name"`
	Typ        string          `json:"typ"`
	SigningKey privateJWK      `json:"signing_key"`
	Kid        string          `json:"kid"`
	Claims     json.RawMessage `json:"claims,omitempty"`
	// Audience is the verifier's own identifier, for token types whose
	// verification checks aud.
	Audience string `json:"audience,omitempty"`
	// Token is the exact compact serialization (derived), or, for a Reject
	// case, a fixed token that verification must refuse.
	Token string `json:"token"`
	// Reject, when set, says why Token must fail verification; such a
	// token is not minted or regenerated.
	Reject string `json:"reject,omitempty"`
	// Randomized marks an algorithm with randomized signatures (ES256):
	// the stored token is checked by verification rather than by byte
	// comparison with a fresh mint.
	Randomized bool `json:"randomized,omitempty"`
}

func mintVector(t *testing.T, c jwtCase) string {
	t.Helper()
	priv := c.SigningKey.signer(t)
	var (
		tok string
		err error
	)
	switch c.Typ {
	case TypAgent:
		var claims AgentClaims
		mustDecodeStrict(t, c.Claims, &claims)
		tok, err = MintAgentToken(claims, priv, c.Kid)
	case TypAuth:
		var claims AuthClaims
		mustDecodeStrict(t, c.Claims, &claims)
		tok, err = MintAuthToken(claims, priv, c.Kid)
	case TypResource:
		var claims ResourceClaims
		mustDecodeStrict(t, c.Claims, &claims)
		tok, err = MintResourceToken(claims, priv, c.Kid)
	default:
		t.Fatalf("%s: unknown typ %q", c.Name, c.Typ)
	}
	if err != nil {
		t.Fatalf("%s: mint: %v", c.Name, err)
	}
	return tok
}

func mustDecodeStrict(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
}

func runJWTVectors(t *testing.T, raw json.RawMessage, update bool) any {
	cases := decodeCases[jwtCase](t, raw)
	for i, c := range cases {
		if c.Reject != "" {
			if err := verifyVectorToken(t, c); err == nil {
				t.Errorf("%s: verified, want rejection (%s)", c.Name, c.Reject)
			}
			continue
		}
		got := mintVector(t, c)
		if update {
			cases[i].Token = got
			continue
		}
		if !c.Randomized && got != c.Token {
			t.Errorf("%s: minted token differs from vector\n got %s\nwant %s", c.Name, got, c.Token)
		}
		if c.Randomized && headerOf(t, got) != headerOf(t, c.Token) {
			t.Errorf("%s: minted header %s, vector header %s", c.Name, headerOf(t, got), headerOf(t, c.Token))
		}
		// The payload carries exactly the vector's claims.
		parts := strings.Split(c.Token, ".")
		if len(parts) != 3 {
			t.Fatalf("%s: not a compact JWS", c.Name)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var gotClaims, wantClaims map[string]any
		if err := json.Unmarshal(payload, &gotClaims); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.Claims, &wantClaims); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotClaims, wantClaims) {
			t.Errorf("%s: payload %s, want %s", c.Name, payload, c.Claims)
		}
		// And it verifies against the published (public) key.
		if err := verifyVectorToken(t, c); err != nil {
			t.Errorf("%s: verify: %v", c.Name, err)
		}
	}
	return cases
}

func headerOf(t *testing.T, token string) string {
	t.Helper()
	h, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("not a compact JWS: %q", token)
	}
	return h
}

func verifyVectorToken(t *testing.T, c jwtCase) error {
	t.Helper()
	ctx := context.Background()
	// The issuer whose key is pinned comes from the token itself, so
	// reject cases need not repeat their claims.
	var iss struct {
		Iss string `json:"iss"`
	}
	parts := strings.Split(c.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("%s: not a compact JWS", c.Name)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &iss); err != nil {
		t.Fatal(err)
	}
	resolver := StaticResolver{iss.Iss: JWKS{Keys: []JWK{c.SigningKey.JWK}}}
	switch c.Typ {
	case TypAgent:
		_, err := VerifyAgentToken(ctx, c.Token, VerifyAgentTokenOptions{Resolver: resolver, RequireProviderClaims: true})
		return err
	case TypAuth:
		_, err := VerifyAuthToken(ctx, c.Token, c.Audience, resolver)
		return err
	}
	return nil
}

// --- http-signature -------------------------------------------------------

type vectorRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

func (v vectorRequest) build(t *testing.T) *http.Request {
	t.Helper()
	var body io.Reader
	if v.Body != "" {
		body = strings.NewReader(v.Body)
	}
	req, err := http.NewRequest(v.Method, v.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(v.Headers))
	for k := range v.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		req.Header.Set(k, v.Headers[k])
	}
	return req
}

type httpSignatureCase struct {
	Name       string     `json:"name"`
	SigningKey privateJWK `json:"signing_key"`
	// Request is the request before signing; Signature-Key is set.
	Request vectorRequest `json:"request"`
	// Signed holds the headers signing adds (derived): Signature-Input,
	// Signature, and Content-Digest when there is a body.
	Signed map[string]string `json:"signed"`
	// Tamper, when set, replaces request members after signing.
	Tamper *vectorRequest `json:"tamper,omitempty"`
	// Verify configures the verifier.
	Verify *vectorVerify `json:"verify,omitempty"`
	// Expect is "valid", or the Signature-Error code verification yields.
	Expect string `json:"expect"`
}

type vectorVerify struct {
	// AtOffset is the verifier's clock, in seconds after the signature's
	// created parameter (default 0).
	AtOffset            int64    `json:"at_offset,omitempty"`
	WindowSeconds       int64    `json:"window_seconds,omitempty"`
	RequiredComponents  []string `json:"required_components,omitempty"`
	RequireBodyCoverage bool     `json:"require_body_coverage,omitempty"`
}

var signedHeaderNames = []string{HeaderSignatureInput, HeaderSignature, "Content-Digest"}

func runHTTPSignatureVectors(t *testing.T, raw json.RawMessage, update bool) any {
	cases := decodeCases[httpSignatureCase](t, raw)
	for i, c := range cases {
		key := c.SigningKey.signer(t)
		pub, err := c.SigningKey.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if update {
			req := c.Request.build(t)
			if err := SignRequest(req, key, ""); err != nil {
				t.Fatalf("%s: sign: %v", c.Name, err)
			}
			cases[i].Signed = map[string]string{}
			for _, h := range signedHeaderNames {
				if v := req.Header.Get(h); v != "" {
					cases[i].Signed[h] = v
				}
			}
			continue
		}
		v := c.Request
		if c.Tamper != nil {
			v = mergeTamper(v, *c.Tamper)
		}
		headers := map[string]string{}
		for k, val := range v.Headers {
			headers[k] = val
		}
		for k, val := range c.Signed {
			headers[k] = val
		}
		v.Headers = headers
		req := v.build(t)

		si, err := parseSignatureInput(req, DefaultSignatureLabel)
		if err != nil || si.created == nil {
			t.Fatalf("%s: vector Signature-Input: %v", c.Name, err)
		}
		opts := RequestVerifyOptions{}
		offset := int64(0)
		if c.Verify != nil {
			offset = c.Verify.AtOffset
			opts.Window = time.Duration(c.Verify.WindowSeconds) * time.Second
			opts.RequiredComponents = c.Verify.RequiredComponents
			opts.RequireBodyCoverage = c.Verify.RequireBodyCoverage
		}
		at := time.Unix(*si.created+offset, 0)
		opts.Now = func() time.Time { return at }

		err = VerifyRequestWithOptions(req, pub, opts)
		switch c.Expect {
		case "valid":
			if err != nil {
				t.Errorf("%s: verify: %v", c.Name, err)
			}
		default:
			se, ok := SignatureErrorFor(err)
			if !ok || se.Code != c.Expect {
				t.Errorf("%s: err = %v (Signature-Error %q), want %s", c.Name, err, se.Code, c.Expect)
			}
		}
	}
	return cases
}

func mergeTamper(base, tamper vectorRequest) vectorRequest {
	if tamper.Method != "" {
		base.Method = tamper.Method
	}
	if tamper.URL != "" {
		base.URL = tamper.URL
	}
	if tamper.Body != "" {
		base.Body = tamper.Body
	}
	if len(tamper.Headers) > 0 {
		h := map[string]string{}
		for k, v := range base.Headers {
			h[k] = v
		}
		for k, v := range tamper.Headers {
			h[k] = v
		}
		base.Headers = h
	}
	return base
}
