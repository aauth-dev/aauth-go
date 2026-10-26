package sandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

func TestConfigDefaults(t *testing.T) {
	cfg, err := Config{Remote: map[string]string{RolePS: "https://ps.example.com/"}}.withDefaults("/srv/root")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != filepath.Join("/srv/root", ".aauth-sandbox") || cfg.Consent != ConsentAuto || cfg.Person != DefaultPerson {
		t.Fatalf("defaults %+v", cfg)
	}
	if got := cfg.URL(RoleAP); got != "https://ap.aauth.test" {
		t.Errorf("ap URL %q", got)
	}
	if got := cfg.URL(RolePS); got != "https://ps.example.com" {
		t.Errorf("remote ps URL %q", got)
	}
	if cfg.Local(RolePS) || !cfg.Local(RoleAS) {
		t.Error("local/remote roles")
	}
	if got := cfg.HostsLine(); got != "127.0.0.1 ap.aauth.test as.aauth.test resource.aauth.test docs.aauth.test" {
		t.Errorf("hosts line %q", got)
	}
	for name, bad := range map[string]Config{
		"consent":      {Consent: "sometimes"},
		"unknown host": {Hosts: map[string]string{"cache": "x.test"}},
		"http remote":  {Remote: map[string]string{RoleAS: "http://as.example"}},
	} {
		if _, err := bad.withDefaults("/srv/root"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Every role remote is a signing helper on its own.
	allRemote := Config{Remote: map[string]string{RoleAP: "https://a.example", RolePS: "https://b.example", RoleAS: "https://c.example",
		RoleResource: "https://d.example", RoleDocs: "https://e.example"}}
	cfg, err = allRemote.withDefaults("/srv/root")
	if err != nil {
		t.Fatalf("all remote: %v", err)
	}
	if len(cfg.LocalHosts()) != 0 {
		t.Errorf("all remote: local hosts %v", cfg.LocalHosts())
	}
}

func TestCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("CA key mode %v", info.Mode().Perm())
	}
	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Cert.Equal(ca.Cert) {
		t.Fatal("CA not reloaded")
	}
	cert, err := ca.IssueServerCert([]string{"ps.aauth.test", "as.aauth.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("as.aauth.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Leaf.Verify(x509VerifyOptions(ca)); err != nil {
		t.Fatalf("server cert does not chain to the CA: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, CACertFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "half") {
		t.Fatalf("half a CA: %v", err)
	}
}

func TestTraceBounded(t *testing.T) {
	tr := NewTrace(3)
	for i := 0; i < 5; i++ {
		tr.Add(Exchange{From: "agent", To: "ps", Request: Message{URL: string(rune('a' + i))}})
	}
	ex := tr.Exchanges()
	if len(ex) != 3 || ex[0].Request.URL != "c" {
		t.Fatalf("trace %+v", ex)
	}
	if got := string(traceBody([]byte("plain text"))); got != `"plain text"` {
		t.Errorf("text body %s", got)
	}
}

func TestRouting(t *testing.T) {
	sb, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := sb.Handler()
	for host, want := range map[string]int{"ps.aauth.test": http.StatusOK, "PS.aauth.test:443": http.StatusOK, "nope.aauth.test": http.StatusNotFound} {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/.well-known/aauth-person.json", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d: %s", host, rec.Code, want, rec.Body)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://ps.aauth.test/pending/x", nil)
	req.Host = "ps.aauth.test"
	rec := httptest.NewRecorder()
	absoluteLocation("https://ps.aauth.test", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/pending/x")
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rec, req)
	if got := rec.Header().Get("Location"); got != "https://ps.aauth.test/pending/x" {
		t.Errorf("Location %q", got)
	}
}

func TestSignerPrepare(t *testing.T) {
	sb, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sg := sb.Signer()
	ctx := context.Background()
	resource, err := url.Parse(sb.Config().URL(RoleResource) + "/api/documents")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := url.Parse(sb.Config().URL(RolePS) + PathToken)
	if err != nil {
		t.Fatal(err)
	}

	in := http.Header{}
	in.Set(HeaderPresent, PresentHWK)
	in.Set(HeaderFrom, "spoofed")
	in.Set("Connection", "keep-alive")
	in.Set("Signature", "sig=:old:")
	in.Set("X-Custom", "kept")
	out, err := sg.prepare(ctx, http.MethodGet, resource, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{HeaderPresent, HeaderFrom, "Connection"} {
		if out.Header.Get(h) != "" {
			t.Errorf("%s forwarded", h)
		}
	}
	if out.Header.Get("X-Custom") != "kept" || !strings.HasPrefix(out.Header.Get("Signature-Key"), "sig=hwk") || out.Header.Get("Signature") == "sig=:old:" {
		t.Errorf("headers %v", out.Header)
	}
	if out.Header.Get("AAuth-Capabilities") != "interaction" {
		t.Errorf("capabilities %q", out.Header.Get("AAuth-Capabilities"))
	}

	in = http.Header{}
	in.Set(HeaderPresent, PresentJKTJWT)
	out, err = sg.prepare(ctx, http.MethodPost, ps, in, []byte(`{"resource_token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Header.Get("Signature-Key"), "sig=jkt-jwt") || out.Header.Get("Content-Digest") == "" {
		t.Errorf("jkt-jwt headers %v", out.Header)
	}
	if out.Header.Get("AAuth-Capabilities") != "" {
		t.Error("capabilities header sent to the PS")
	}

	for _, bad := range []string{PresentPerson, "bearer"} {
		in = http.Header{}
		in.Set(HeaderPresent, bad)
		if _, err := sg.prepare(ctx, http.MethodGet, resource, in, nil); err == nil {
			t.Errorf("%s without a token accepted", bad)
		}
	}

	in = http.Header{}
	in.Set(HeaderPresent, PresentNone)
	in[HeaderCapabilitiesOverride] = []string{""}
	out, err = sg.prepare(ctx, http.MethodGet, resource, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Header.Get("Signature") != "" || out.Header.Get("AAuth-Capabilities") != "" {
		t.Errorf("unsigned request headers %v", out.Header)
	}

	if err := sg.ListenAndServe(ctx, "0.0.0.0:0"); err == nil {
		t.Error("the helper listened on a public address")
	}
}

func TestAddCapabilitiesMember(t *testing.T) {
	caps := []string{"interaction"}
	for in, want := range map[string]string{
		`{}`:                           `{"capabilities":["interaction"]}`,
		`{"b":1,"a":2}`:                `{"b":1,"a":2,"capabilities":["interaction"]}`,
		`{"capabilities":["payment"]}`: `{"capabilities":["payment"]}`,
		`[1]`:                          `[1]`,
		`not json`:                     `not json`,
	} {
		got, err := addCapabilitiesMember([]byte(in), caps)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if got, err := addCapabilitiesMember([]byte(`{}`), nil); err != nil || string(got) != `{}` {
		t.Errorf("no capabilities: %s, %v", got, err)
	}
}

func TestTLSConfig(t *testing.T) {
	sb, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := sb.TLSConfig(); len(c.Certificates) != 1 || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("tls config %+v", c)
	}
}

func x509VerifyOptions(ca *CA) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: ca.Pool(), DNSName: "ps.aauth.test"}
}

func TestPresentation(t *testing.T) {
	jws := func(typ string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"`+typ+`"}`)) + ".e30.c2ln"
	}
	tests := []struct {
		name           string
		headers        map[string]string
		present, token string
		wantErr        bool
	}{
		{"nothing: the helper's agent token", nil, PresentAgent, "", false},
		{"sandbox headers win", map[string]string{HeaderPresent: "PERSON", HeaderToken: "t", "Signature-Key": "sig=hwk"}, PresentPerson, "t", false},
		{"a token alone presents it as the agent", map[string]string{HeaderToken: "t"}, "", "t", false},
		{"jwt without a token", map[string]string{"Signature-Key": "sig=jwt"}, PresentAgent, "", false},
		{"agent token", map[string]string{"Signature-Key": `sig=jwt;jwt="` + jws(aauth.TypAgent) + `"`}, PresentAgent, jws(aauth.TypAgent), false},
		{"person token", map[string]string{"Signature-Key": `sig=jwt;jwt="` + jws(aauth.TypPerson) + `"`}, PresentPerson, jws(aauth.TypPerson), false},
		{"auth token", map[string]string{"Signature-Key": `sig=jwt;jwt="` + jws(aauth.TypAuth) + `"`}, PresentAuth, jws(aauth.TypAuth), false},
		{"hwk", map[string]string{"Signature-Key": "sig=hwk"}, PresentHWK, "", false},
		{"jkt-jwt", map[string]string{"Signature-Key": "sig=jkt-jwt"}, PresentJKTJWT, "", false},
		{"another typ", map[string]string{"Signature-Key": `sig=jwt;jwt="` + jws("JWT") + `"`}, "", "", true},
		{"not a JWS", map[string]string{"Signature-Key": `sig=jwt;jwt="nope"`}, "", "", true},
		{"another scheme", map[string]string{"Signature-Key": "sig=jwks_uri"}, "", "", true},
		{"malformed", map[string]string{"Signature-Key": "sig=("}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := http.Header{}
			for k, v := range tt.headers {
				in.Set(k, v)
			}
			present, token, err := presentation(in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("presentation() error = %v, want error %v", err, tt.wantErr)
			}
			if present != tt.present || token != tt.token {
				t.Errorf("presentation() = %q, %q; want %q, %q", present, token, tt.present, tt.token)
			}
		})
	}
}
