package aauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// psSigner returns a ServerSigner for a PS whose metadata and JWKS are
// served by s, with an ES256 key published under kid "ps-key-1".
func psSigner(t *testing.T) (*jwksServer, ServerSigner) {
	t.Helper()
	key, err := GenerateKey(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = "ps-key-1"
	s := newJWKSServer(t, j)
	return s, ServerSigner{Issuer: s.srv.URL, DWK: WellKnownPerson, Kid: j.Kid, Key: key}
}

func serverRequest(t *testing.T, signer ServerSigner) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"resource_token":"x","presented_token":"y"}`
	setBody(req, body)
	req.Header.Set("Content-Type", "application/json")
	if err := signer.SignRequest(req); err != nil {
		t.Fatal(err)
	}
	setBody(req, body)
	return req
}

func TestAttachSignatureKeyJWKSURI(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://as.example/", nil)
	AttachSignatureKeyJWKSURI(r, "https://ps.example", WellKnownPerson, "key-1")
	want := `sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="key-1"`
	if got := r.Header.Get(HeaderSignatureKey); got != want {
		t.Fatalf("Signature-Key = %s, want %s", got, want)
	}
	if err := (ServerSigner{Issuer: "https://ps.example"}).SignRequest(r); err == nil {
		t.Fatal("incomplete ServerSigner accepted")
	}
}

func TestVerifyServerRequest(t *testing.T) {
	s, signer := psSigner(t)
	ctx := context.Background()
	opts := VerifyServerOptions{
		Resolver:  NewJWKSResolver(nil),
		DWKs:      []string{WellKnownPerson},
		Signature: RequestVerifyOptions{RequireBodyCoverage: true},
	}
	caller, err := VerifyServerRequest(ctx, serverRequest(t, signer), opts)
	if err != nil {
		t.Fatal(err)
	}
	if caller.ID != s.srv.URL || caller.DWK != WellKnownPerson || caller.Kid != "ps-key-1" {
		t.Fatalf("caller = %+v", caller)
	}

	// A tampered body fails the signature.
	req := serverRequest(t, signer)
	setBody(req, `{"resource_token":"z","presented_token":"y"}`)
	if _, err := VerifyServerRequest(ctx, req, opts); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered: err = %v", err)
	}
}

func TestVerifyServerRequestRejections(t *testing.T) {
	s, signer := psSigner(t)
	ctx := context.Background()
	code := func(err error) string {
		t.Helper()
		e, ok := SignatureErrorFor(err)
		if !ok {
			t.Fatalf("unclassified error %v", err)
		}
		return e.Code
	}

	// An agent's jwt scheme is not accepted here; the 401 names jwks_uri.
	a := testAgent(t)
	req := signedTestRequest(t, a, "", "")
	_, err := VerifyServerRequest(ctx, req, VerifyServerOptions{})
	if code(err) != SigErrUnsupportedScheme {
		t.Fatalf("jwt scheme: err = %v", err)
	}
	rec := httptest.NewRecorder()
	WriteSignatureFailure(rec, err)
	if got := rec.Header().Get(HeaderAcceptSignatureScheme); got != SchemeJWKSURI {
		t.Fatalf("Accept-Signature-Scheme = %q", got)
	}

	// Role restriction and signer trust are checked before any fetch.
	before := s.jwksFetches.Load()
	_, err = VerifyServerRequest(ctx, serverRequest(t, signer), VerifyServerOptions{DWKs: []string{WellKnownAccess}})
	if code(err) != SigErrInvalidKey {
		t.Fatalf("dwk: err = %v", err)
	}
	_, err = VerifyServerRequest(ctx, serverRequest(t, signer), VerifyServerOptions{TrustSigner: func(string, string) bool { return false }})
	if code(err) != SigErrInvalidKey {
		t.Fatalf("trust: err = %v", err)
	}
	if s.jwksFetches.Load() != before {
		t.Fatal("fetched keys for a rejected signer")
	}

	// Missing parameters.
	req = serverRequest(t, signer)
	req.Header.Set(HeaderSignatureKey, `sig=jwks_uri;id="`+s.srv.URL+`";dwk="aauth-person.json"`)
	if _, err := VerifyServerRequest(ctx, req, VerifyServerOptions{}); code(err) != SigErrInvalidSignature {
		t.Fatalf("no kid: err = %v", err)
	}

	// Unknown kid.
	other := signer
	other.Kid = "nope"
	if _, err := VerifyServerRequest(ctx, serverRequest(t, other), VerifyServerOptions{Resolver: NewJWKSResolver(nil)}); code(err) != SigErrUnknownKey {
		t.Fatalf("unknown kid: err = %v", err)
	}

	// The metadata claims a different issuer than id.
	evil := "https://evil.example"
	s.update(func(s *jwksServer) { s.issuer = &evil })
	if _, err := VerifyServerRequest(ctx, serverRequest(t, signer), VerifyServerOptions{Resolver: NewJWKSResolver(nil)}); code(err) != SigErrIssuerMismatch {
		t.Fatalf("issuer mismatch: err = %v", err)
	}
}

func TestVerifyServerRequestRekey(t *testing.T) {
	s, signer := psSigner(t)
	clock := &fakeClock{t: time.Now()}
	opts := VerifyServerOptions{Resolver: JWKSResolver{Cache: &JWKSCache{Now: clock.Now}}}
	ctx := context.Background()
	if _, err := VerifyServerRequest(ctx, serverRequest(t, signer), opts); err != nil {
		t.Fatal(err)
	}
	// The PS replaces its key under the same kid.
	key, err := GenerateKey(AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = signer.Kid
	s.update(func(s *jwksServer) { s.set = JWKS{Keys: []JWK{j}} })
	signer.Key = key
	clock.Advance(2 * time.Minute)
	if _, err := VerifyServerRequest(ctx, serverRequest(t, signer), opts); err != nil {
		t.Fatalf("after re-key: %v", err)
	}
}
