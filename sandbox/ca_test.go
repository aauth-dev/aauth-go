package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCANameConstraints(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Cert
	if !c.PermittedDNSDomainsCritical || !slices.Equal(c.PermittedDNSDomains, []string{"aauth.test", "localhost"}) || len(c.PermittedIPRanges) != 2 {
		t.Fatalf("constraints: critical %v, DNS %v, IP %v", c.PermittedDNSDomainsCritical, c.PermittedDNSDomains, c.PermittedIPRanges)
	}
	if v := c.NotAfter.Sub(c.NotBefore); v > 366*24*time.Hour {
		t.Errorf("CA valid for %v", v)
	}
	if ca.Replaced != "" {
		t.Errorf("a new CA reports Replaced %q", ca.Replaced)
	}

	if _, err := ca.IssueServerCert([]string{"example.com"}); err == nil {
		t.Error("issued a certificate for a name outside the CA's domains")
	}
	leaf, err := ca.IssueServerCert([]string{"ps.aauth.test"})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.NotAfter.After(c.NotAfter) {
		t.Errorf("leaf outlives the CA: %v > %v", leaf.Leaf.NotAfter, c.NotAfter)
	}
	for _, name := range []string{"ps.aauth.test", "localhost", "127.0.0.1", "::1"} {
		opts := x509VerifyOptions(ca)
		opts.DNSName = name
		if _, err := leaf.Leaf.Verify(opts); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
	}

	// A certificate the CA key signs for another site does not verify,
	// even for a client that trusts the CA.
	for _, tc := range []struct {
		dns []string
		ip  []net.IP
	}{{dns: []string{"example.com"}}, {ip: []net.IP{net.IPv4(192, 0, 2, 1)}}} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: "x"}, DNSNames: tc.dns, IPAddresses: tc.ip,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, c, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forged.Verify(x509.VerifyOptions{Roots: ca.Pool()}); err == nil {
			t.Errorf("a certificate for %v %v verified", tc.dns, tc.ip)
		}
	}
}

// writeTestCA writes a CA made by newCAPEM to dir.
func writeTestCA(t *testing.T, dir string, domains []string, validity time.Duration) {
	t.Helper()
	certPEM, keyPEM, err := newCAPEM(domains, time.Now(), validity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CACertFile), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCAReplaced(t *testing.T) {
	for _, tc := range []struct {
		name     string
		domains  []string
		validity time.Duration
		load     []string
		reason   string
		covers   []string
	}{
		{"unconstrained", nil, 5 * 365 * 24 * time.Hour, nil, "no name constraints", []string{"aauth.test"}},
		{"expiring", []string{"aauth.test", "localhost"}, 10 * 24 * time.Hour, nil, "expires", []string{"aauth.test"}},
		{"another domain", []string{"aauth.test", "localhost"}, caValidity, []string{"example.dev"}, "did not cover example.dev", []string{"aauth.test", "example.dev"}},
		{"current", []string{"aauth.test", "localhost"}, caValidity, []string{"api.aauth.test"}, "", []string{"aauth.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCA(t, dir, tc.domains, tc.validity)
			ca, err := LoadOrCreateCA(dir, tc.load...)
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" != (ca.Replaced == "") || !strings.Contains(ca.Replaced, tc.reason) {
				t.Fatalf("Replaced %q, want %q", ca.Replaced, tc.reason)
			}
			for _, d := range tc.covers {
				if !permits(ca.Cert.PermittedDNSDomains, d) {
					t.Errorf("the CA does not cover %s: %v", d, ca.Cert.PermittedDNSDomains)
				}
			}
			again, err := LoadOrCreateCA(dir, tc.load...)
			if err != nil {
				t.Fatal(err)
			}
			if again.Replaced != "" || !again.Cert.Equal(ca.Cert) {
				t.Fatalf("the replacement was not kept: %q", again.Replaced)
			}
		})
	}
}

func TestCAKeyMismatch(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(other); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(other, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Fatalf("mismatched CA key: %v", err)
	}
}

func TestCADomains(t *testing.T) {
	cfg, err := Config{StateDir: t.TempDir(), Upstreams: map[string]string{
		"petstore": "http://127.0.0.1:8080", "api.example.dev": "http://127.0.0.1:8081",
	}}.WithDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.CADomains(); !slices.Equal(got, []string{"aauth.test", "api.example.dev"}) {
		t.Fatalf("CADomains = %v", got)
	}
	// The sandbox serves an upstream outside its domain under the CA.
	h := newHarness(t, Config{Upstreams: map[string]string{"api.example.dev": "http://127.0.0.1:1"}})
	if !permits(h.sb.CA().Cert.PermittedDNSDomains, "api.example.dev") {
		t.Fatalf("CA domains %v", h.sb.CA().Cert.PermittedDNSDomains)
	}
}
