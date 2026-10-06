package aauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
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
