package aauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yaronf/httpsign"
)

func signedTestRequest(t *testing.T, a *Agent, body string, keyid string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://ps.example/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		setBody(req, body)
		req.Header.Set("Content-Type", "application/json")
	}
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, keyid); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		setBody(req, body) // SignRequest consumed the body for content-digest
	}
	return req
}

func TestSignRequestParameters(t *testing.T) {
	a := testAgent(t)
	req := signedTestRequest(t, a, `{"resource_token":"x"}`, "")
	in := req.Header.Get(HeaderSignatureInput)
	if strings.Contains(in, "keyid") || strings.Contains(in, "alg=") {
		t.Fatalf("Signature-Input carries keyid/alg: %s", in)
	}
	si, err := parseSignatureInput(req, DefaultSignatureLabel)
	if err != nil {
		t.Fatal(err)
	}
	if si.created == nil {
		t.Fatal("created missing")
	}
	for _, c := range []string{"@method", "@authority", "@path", "signature-key", "content-digest", "content-type"} {
		if !slices.Contains(si.components, c) {
			t.Errorf("component %q not covered: %v", c, si.components)
		}
	}

	// keyid is still emitted when a caller explicitly asks for it.
	req = signedTestRequest(t, a, "", a.Thumbprint())
	if !strings.Contains(req.Header.Get(HeaderSignatureInput), `keyid="`+a.Thumbprint()+`"`) {
		t.Fatalf("explicit keyid not emitted: %s", req.Header.Get(HeaderSignatureInput))
	}
}

func TestVerifyRequestCreatedWindow(t *testing.T) {
	a := testAgent(t)
	pub := a.Key.Public()
	req := signedTestRequest(t, a, "", "")
	si, err := parseSignatureInput(req, DefaultSignatureLabel)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Unix(*si.created, 0)
	at := func(d time.Duration) RequestVerifyOptions {
		return RequestVerifyOptions{Now: func() time.Time { return created.Add(d) }}
	}
	if err := VerifyRequestWithOptions(req, pub, at(DefaultSignatureWindow)); err != nil {
		t.Fatalf("at the window edge: %v", err)
	}
	err = VerifyRequestWithOptions(req, pub, at(DefaultSignatureWindow+time.Second))
	if !errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrClockSkew) {
		t.Fatalf("stale: err = %v, want ErrSignatureInvalid", err)
	}
	if err := VerifyRequestWithOptions(req, pub, at(-DefaultSignatureWindow-time.Second)); !errors.Is(err, ErrClockSkew) {
		t.Fatalf("future: err = %v, want ErrClockSkew", err)
	}
	o := at(5 * time.Minute)
	o.Window = 10 * time.Minute
	if err := VerifyRequestWithOptions(req, pub, o); err != nil {
		t.Fatalf("custom window: %v", err)
	}

	// VerifyAndExtractAgent applies the same options.
	_, err = VerifyAndExtractAgent(context.Background(), req, VerifyAgentTokenOptions{
		Resolver:  SelfSignedResolver{},
		Signature: at(2 * DefaultSignatureWindow),
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyAndExtractAgent stale: err = %v", err)
	}
}

func TestVerifyRequestRejectsMalformedParameters(t *testing.T) {
	a := testAgent(t)
	pub := a.Key.Public()
	created := regexp.MustCompile(`;created=\d+`)

	req := signedTestRequest(t, a, "", "")
	req.Header.Set(HeaderSignatureInput, created.ReplaceAllString(req.Header.Get(HeaderSignatureInput), ""))
	if err := VerifyRequest(req, pub); !errors.Is(err, ErrSignatureInvalid) || !strings.Contains(err.Error(), "created") {
		t.Fatalf("created missing: err = %v", err)
	}

	req = signedTestRequest(t, a, "", "")
	req.Header.Set(HeaderSignatureInput, req.Header.Get(HeaderSignatureInput)+";expires=1")
	if err := VerifyRequest(req, pub); !errors.Is(err, ErrSignatureInvalid) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: err = %v", err)
	}

	for _, h := range []string{HeaderSignature, HeaderSignatureInput, HeaderSignatureKey} {
		req = signedTestRequest(t, a, "", "")
		req.Header.Del(h)
		if err := VerifyRequest(req, pub); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("%s missing: err = %v", h, err)
		}
	}

	req = signedTestRequest(t, a, "", "")
	req.Header.Set(HeaderSignatureInput, "not a dictionary (")
	if err := VerifyRequest(req, pub); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("malformed Signature-Input: err = %v", err)
	}
}

func TestVerifyRequestRequiredComponents(t *testing.T) {
	a := testAgent(t)
	pub := a.Key.Public()
	req := signedTestRequest(t, a, "", "")
	err := VerifyRequestWithOptions(req, pub, RequestVerifyOptions{RequiredComponents: []string{"content-type", "@query"}})
	var mce *MissingComponentsError
	if !errors.As(err, &mce) || !errors.Is(err, ErrSignatureInput) {
		t.Fatalf("err = %v, want MissingComponentsError", err)
	}
	if !slices.Equal(mce.Missing, []string{"content-type", "@query"}) {
		t.Fatalf("missing = %v", mce.Missing)
	}
	if !slices.Contains(mce.Required, "signature-key") || !slices.Contains(mce.Required, "@query") {
		t.Fatalf("required = %v", mce.Required)
	}
}

// A body of unknown length (an arbitrary reader, ContentLength zero) is
// sent on the wire, so it must be covered by a digest like any other.
func TestSignRequestStreamingBody(t *testing.T) {
	a := testAgent(t)
	const body = `{"hello":"world"}`
	var got *http.Request
	var gotErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotErr = VerifyRequestWithOptions(r, a.Key.Public(), RequestVerifyOptions{RequireBodyCoverage: true})
		if gotErr == nil {
			b, _ := io.ReadAll(r.Body)
			if string(b) != body {
				gotErr = errors.New("server read " + string(b))
			}
		}
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if req.ContentLength != 0 {
		t.Fatalf("ContentLength = %d; the test needs an unknown length", req.ContentLength)
	}
	req.Header.Set("Content-Type", "application/json")
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, ""); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Content-Digest") == "" {
		t.Fatal("streaming body signed without a Content-Digest")
	}
	if !strings.Contains(req.Header.Get("Signature-Input"), "content-digest") {
		t.Fatalf("Signature-Input does not cover content-digest: %s", req.Header.Get("Signature-Input"))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if got == nil || gotErr != nil {
		t.Fatalf("server verification: %v", gotErr)
	}

	// An empty streaming body is no body.
	empty, err := http.NewRequest(http.MethodPost, srv.URL+"/token", io.NopCloser(strings.NewReader("")))
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(empty, tok)
	if err := SignRequest(empty, a.Key, ""); err != nil {
		t.Fatal(err)
	}
	if empty.Body != http.NoBody || empty.Header.Get("Content-Digest") != "" {
		t.Fatalf("empty streaming body: %v digest %q", empty.Body, empty.Header.Get("Content-Digest"))
	}
}

// A body of unknown length is buffered only up to MaxSignedStreamBytes; a
// caller with a larger one supplies its own Content-Digest.
func TestSignRequestStreamingBodyBound(t *testing.T) {
	a := testAgent(t)
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	over := io.NopCloser(io.LimitReader(zeroReader{}, MaxSignedStreamBytes+1))
	req, err := http.NewRequest(http.MethodPost, "https://ps.example/token", over)
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, ""); err == nil {
		t.Fatal("body over MaxSignedStreamBytes was buffered and signed")
	}
	// ContentLength -1 is unknown too, not a known length to digest unbounded.
	req, err = http.NewRequest(http.MethodPost, "https://ps.example/token", io.NopCloser(io.LimitReader(zeroReader{}, MaxSignedStreamBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, ""); err == nil {
		t.Fatal("body of ContentLength -1 over MaxSignedStreamBytes was buffered and signed")
	}

	// With the digest supplied, the body is not read at signing time.
	req, err = http.NewRequest(http.MethodPost, "https://ps.example/token", io.NopCloser(failingReader{}))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
	req.Header.Set("Content-Type", "application/octet-stream")
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, ""); err != nil {
		t.Fatalf("preset Content-Digest: %v", err)
	}
	if !strings.Contains(req.Header.Get("Signature-Input"), "content-digest") {
		t.Fatal("preset Content-Digest not covered")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("body must not be read") }

func TestVerifyRequestAuthority(t *testing.T) {
	a := testAgent(t)
	for _, tc := range []struct {
		name, url, authority string
		wantErr              bool
	}{
		{"same host", "https://resource.example/data", "resource.example", false},
		{"default port", "https://resource.example:443/data", "resource.example", false},
		{"case", "https://Resource.Example/data", "resource.example", false},
		{"explicit port", "https://resource.example:8443/data", "resource.example:8443", false},
		{"other host", "https://evil.example/data", "resource.example", true},
		{"other port", "https://resource.example:8443/data", "resource.example", true},
		{"unset", "https://evil.example/data", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			tok, err := a.MintToken()
			if err != nil {
				t.Fatal(err)
			}
			AttachSignatureKey(req, tok)
			if err := SignRequest(req, a.Key, ""); err != nil {
				t.Fatal(err)
			}
			err = VerifyRequestWithOptions(req, a.Key.Public(), RequestVerifyOptions{Authority: tc.authority})
			if tc.wantErr {
				if !errors.Is(err, ErrWrongAuthority) || !errors.Is(err, ErrSignatureInvalid) {
					t.Fatalf("err = %v, want ErrWrongAuthority", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorityOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://ps.example":      "ps.example",
		"https://PS.example:443":  "ps.example",
		"https://ps.example:8443": "ps.example:8443",
		"http://127.0.0.1:8080/x": "127.0.0.1:8080",
	} {
		got, err := AuthorityOf(in)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("AuthorityOf(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := AuthorityOf("not a url"); err == nil {
		t.Error("AuthorityOf without a host succeeded")
	}
}

// A covered component with tr or req is refused before the body is read:
// either would make the signature library buffer the whole body first.
func TestVerifyRequestRefusesTrailerAndReqComponents(t *testing.T) {
	a := testAgent(t)
	for _, param := range []string{"tr", "req"} {
		req := signedTestRequest(t, a, "", "")
		req.Body = io.NopCloser(failingReader{})
		req.ContentLength = -1
		in := req.Header.Get(HeaderSignatureInput)
		req.Header.Set(HeaderSignatureInput, strings.Replace(in, `"signature-key"`, `"signature-key" "x";`+param, 1))
		err := VerifyRequest(req, a.Key.Public())
		if !errors.Is(err, ErrSignatureInvalid) || !strings.Contains(err.Error(), param+" parameter") {
			t.Fatalf("%s: err = %v", param, err)
		}
	}
}

// A component with parameters does not satisfy a required one:
// "signature-key";key="other" covers another member, not the one in use.
func TestVerifyRequestParameterizedComponentDoesNotCover(t *testing.T) {
	a := testAgent(t)
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://r.example/x", nil)
	req.Header.Set(HeaderSignatureKey, `sig=jwt;jwt="`+tok+`", other=jwt;jwt="x"`)
	f := httpsign.NewFields().AddHeaders("@method", "@authority", "@path").AddDictHeader("signature-key", "other")
	s, err := newHTTPSigner(a.Key, httpsign.NewSignConfig().SignAlg(false).SignCreated(true), *f)
	if err != nil {
		t.Fatal(err)
	}
	in, sig, err := httpsign.SignRequest(DefaultSignatureLabel, *s, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderSignatureInput, in)
	req.Header.Set(HeaderSignature, sig)
	err = VerifyRequest(req, a.Key.Public())
	var mce *MissingComponentsError
	if !errors.As(err, &mce) || !slices.Equal(mce.Missing, []string{"signature-key"}) {
		t.Fatalf("err = %v, want signature-key missing", err)
	}
}

// Verification reads at most MaxBodySize bytes of the body.
func TestVerifyRequestMaxBodySize(t *testing.T) {
	a := testAgent(t)
	body := strings.Repeat("a", 100)
	pub := a.Key.Public()
	opts := RequestVerifyOptions{MaxBodySize: 50}

	// Known length over the limit: refused without reading.
	req := signedTestRequest(t, a, body, "")
	req.Body = io.NopCloser(failingReader{})
	if err := VerifyRequestWithOptions(req, pub, opts); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("known length: err = %v, want ErrBodyTooLarge", err)
	}
	// Unknown length: reading stops just past the limit.
	req = signedTestRequest(t, a, body, "")
	cr := &countingReader{r: zeroReader{}}
	req.Body, req.ContentLength = io.NopCloser(cr), -1
	if err := VerifyRequestWithOptions(req, pub, opts); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("unknown length: err = %v, want ErrBodyTooLarge", err)
	}
	if cr.n > 51 {
		t.Fatalf("read %d bytes for a 50-byte limit", cr.n)
	}
	if e, ok := SignatureErrorFor(ErrBodyTooLarge); !ok || e.Code != SigErrInvalidRequest {
		t.Fatalf("classified as %+v", e)
	}
	// Within the limit, and with no limit, the body verifies and stays
	// readable.
	for _, limit := range []int64{0, 100, -1} {
		req = signedTestRequest(t, a, body, "")
		if err := VerifyRequestWithOptions(req, pub, RequestVerifyOptions{MaxBodySize: limit}); err != nil {
			t.Fatalf("MaxBodySize %d: %v", limit, err)
		}
		if b, err := io.ReadAll(req.Body); err != nil || string(b) != body {
			t.Fatalf("MaxBodySize %d: body after verify = %q, %v", limit, b, err)
		}
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
