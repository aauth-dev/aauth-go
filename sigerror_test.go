package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestSignatureErrorRoundTrip(t *testing.T) {
	e := SignatureError{
		Code:          SigErrInvalidInput,
		RequiredInput: []string{"@method", "@authority", "@path", "signature-key", "content-digest"},
		Params:        map[string]string{"z_ext": "tok", "a_ext": `"str"`},
	}
	want := `error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-digest"), a_ext="str", z_ext=tok`
	if got := e.String(); got != want {
		t.Fatalf("String() = %s\nwant      %s", got, want)
	}
	parsed, err := ParseSignatureError(e.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Code != e.Code || !slices.Equal(parsed.RequiredInput, e.RequiredInput) ||
		parsed.Params["a_ext"] != `"str"` || parsed.Params["z_ext"] != "tok" {
		t.Fatalf("parsed %+v", parsed)
	}
	// Absent header → nil, no error.
	if p, err := ParseSignatureError(""); p != nil || err != nil {
		t.Fatalf("empty: %+v, %v", p, err)
	}
	// Missing required member, malformed dictionaries, wrong member types.
	for _, bad := range []string{
		`supported_algorithms=("x")`,
		`error=`,
		`error=("a")`,
		`error=1`,
		`error=invalid_input, required_input=x`,
		`error=invalid_input, required_input=(1 2)`,
	} {
		if _, err := ParseSignatureError(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A bare (Boolean true) extension member is preserved.
	parsed, err = ParseSignatureError(`error=cache_miss, flag`)
	if err != nil || parsed.Params["flag"] != "?1" {
		t.Fatalf("bare member: %+v, %v", parsed, err)
	}
}

func TestWriteSignatureError(t *testing.T) {
	for _, c := range []struct {
		code       string
		wantHeader string
		wantValue  string
	}{
		{SigErrInvalidSignature, "", ""},
		{SigErrUnsupportedAlgorithm, HeaderAcceptSignatureAlg, "Ed25519, ES256"},
		{SigErrUnsupportedScheme, HeaderAcceptSignatureScheme, "jwt"},
	} {
		rec := httptest.NewRecorder()
		WriteSignatureError(rec, SignatureError{Code: c.code}, "detail")
		res := rec.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", c.code, res.StatusCode)
		}
		se, err := SignatureErrorFromResponse(res)
		if err != nil || se == nil || se.Code != c.code {
			t.Fatalf("%s: header: %+v, %v", c.code, se, err)
		}
		if c.wantHeader != "" && res.Header.Get(c.wantHeader) != c.wantValue {
			t.Fatalf("%s: %s = %q", c.code, c.wantHeader, res.Header.Get(c.wantHeader))
		}
		schemes, algs, err := AcceptSignatureFromResponse(res)
		if err != nil {
			t.Fatal(err)
		}
		if c.code == SigErrUnsupportedAlgorithm && !slices.Equal(algs, []string{AlgEd25519, AlgES256}) {
			t.Fatalf("algs = %v", algs)
		}
		if c.code == SigErrUnsupportedScheme && !slices.Equal(schemes, []string{SchemeJWT}) {
			t.Fatalf("schemes = %v", schemes)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("content-type %q", ct)
		}
		var pd map[string]any
		if err := json.NewDecoder(res.Body).Decode(&pd); err != nil {
			t.Fatal(err)
		}
		closeBody(res.Body)
		if typ, _ := pd["type"].(string); typ != "urn:ietf:params:sig-error:"+c.code {
			t.Fatalf("problem type %q", pd["type"])
		}
		if pd["status"].(float64) != 401 {
			t.Fatalf("problem status %v", pd["status"])
		}
	}
}

func TestAcceptSignatureIgnoresUnknownMembers(t *testing.T) {
	res := &http.Response{Header: http.Header{}}
	res.Header.Set(HeaderAcceptSignatureAlg, `Ed25519, "quoted", ES256;x=1`)
	_, algs, err := AcceptSignatureFromResponse(res)
	if err != nil || !slices.Equal(algs, []string{"Ed25519", "ES256"}) {
		t.Fatalf("algs = %v, %v", algs, err)
	}
	res.Header.Set(HeaderAcceptSignatureScheme, "(")
	if _, _, err := AcceptSignatureFromResponse(res); err == nil {
		t.Fatal("malformed list accepted")
	}
}

func TestSignatureErrorFor(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{&MissingComponentsError{Required: []string{"@method"}, Missing: []string{"@method"}}, SigErrInvalidInput},
		{fmt.Errorf("x: %w", ErrClockSkew), SigErrClockSkew},
		{fmt.Errorf("x: %w", ErrUnsupportedScheme), SigErrUnsupportedScheme},
		{fmt.Errorf("cnf.jwk: %w", ErrUnsupportedAlgorithm), SigErrUnsupportedAlgorithm},
		{fmt.Errorf("x: %w", ErrInvalidKey), SigErrInvalidKey},
		{fmt.Errorf("x: %w", ErrUnknownKey), SigErrUnknownKey},
		{fmt.Errorf("x: %w", ErrIssuerMissing), SigErrIssuerMissing},
		{fmt.Errorf("x: %w", ErrIssuerMismatch), SigErrIssuerMismatch},
		{fmt.Errorf("x: %w", ErrRevoked), SigErrRevokedJWT},
		{fmt.Errorf("%w: %w", ErrExpired, errors.New("exp")), SigErrExpiredJWT},
		{fmt.Errorf("%w: bad", ErrInvalidToken), SigErrInvalidJWT},
		{ErrWrongTokenType, SigErrInvalidJWT},
		{ErrMissingClaim, SigErrInvalidJWT},
		{fmt.Errorf("%w: x", ErrSignatureInvalid), SigErrInvalidSignature},
		{ErrMissingSigKey, SigErrInvalidSignature},
		{ErrBadSigKey, SigErrInvalidSignature},
	}
	for _, c := range cases {
		e, ok := SignatureErrorFor(c.err)
		if !ok || e.Code != c.code {
			t.Errorf("%v: got %q (%v), want %q", c.err, e.Code, ok, c.code)
		}
	}
	if e, ok := SignatureErrorFor(&MissingComponentsError{Required: []string{"a", "b"}}); !ok || !slices.Equal(e.RequiredInput, []string{"a", "b"}) {
		t.Fatalf("required_input = %v", e.RequiredInput)
	}
	if _, ok := SignatureErrorFor(errors.New("dial tcp: refused")); ok {
		t.Fatal("unrelated error classified")
	}
	if _, ok := SignatureErrorFor(nil); ok {
		t.Fatal("nil classified")
	}

	rec := httptest.NewRecorder()
	WriteSignatureFailure(rec, errors.New("dial tcp: refused"))
	if se, err := ParseSignatureError(rec.Header().Get(HeaderSignatureError)); err != nil || se.Code != SigErrInvalidSignature || rec.Code != 401 {
		t.Fatalf("unclassified failure: %+v, %v, %d", se, err, rec.Code)
	}
}

func TestParseSignatureKeyMember(t *testing.T) {
	req := func(v string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://resource.example/", nil)
		if v != "" {
			r.Header.Set(HeaderSignatureKey, v)
		}
		return r
	}
	// Canonical and whitespace-tolerant forms; other labels are ignored
	// whatever their scheme (signature-key §3).
	for _, v := range []string{
		`sig=jwt;jwt="a.b.c"`,
		`sig=jwt; jwt="a.b.c"`,
		`other=hwk;kty="OKP", sig=jwt;jwt="a.b.c"`,
		`future=newscheme;x=1, sig=jwt;jwt="a.b.c";cache`,
	} {
		tok, err := ParseSignatureKey(req(v))
		if err != nil || tok != "a.b.c" {
			t.Errorf("%q: %q, %v", v, tok, err)
		}
	}
	sk, err := ParseSignatureKeyMember(req(`sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="k1"`), "sig")
	if err != nil || sk.Scheme != SchemeJWKSURI || sk.Params["id"] != "https://ps.example" || sk.Params["dwk"] != "aauth-person.json" || sk.Params["kid"] != "k1" {
		t.Fatalf("jwks_uri member: %+v, %v", sk, err)
	}
	for _, c := range []struct {
		v    string
		want error
	}{
		{"", ErrMissingSigKey},
		{`other=jwt;jwt="a.b.c"`, ErrBadSigKey},
		{`sig="jwt";jwt="a.b.c"`, ErrBadSigKey},
		{`sig=(jwt)`, ErrBadSigKey},
		{`sig=jwt;jwt=x`, ErrBadSigKey},
		{`sig=jwt`, ErrBadSigKey},
		{`sig=jwt;jwt="a`, ErrBadSigKey},
		{`sig=hwk;kty="OKP"`, ErrUnsupportedScheme},
		{`sig=x-unregistered`, ErrUnsupportedScheme},
	} {
		if _, err := ParseSignatureKey(req(c.v)); !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.v, err, c.want)
		}
	}
}

func TestAttachSignatureKeyCanonical(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://resource.example/", nil)
	AttachSignatureKey(r, "a.b.c")
	if got := r.Header.Get(HeaderSignatureKey); got != `sig=jwt;jwt="a.b.c"` {
		t.Fatalf("Signature-Key = %s", got)
	}
}
