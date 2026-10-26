package sandbox

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CA file names in the state directory.
const (
	CACertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"
)

// CA validity. A CA is replaced when it has less than caRenewBefore left,
// so it must be trusted again about once a year.
const (
	caValidity    = 365 * 24 * time.Hour
	caRenewBefore = 30 * 24 * time.Hour
)

// CA is the sandbox's development certificate authority. It is name
// constrained: it can issue certificates only for its Domains (and their
// subdomains) and the loopback addresses, so trusting it does not let
// its key vouch for any other site.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer

	// Replaced says why LoadOrCreateCA replaced the CA that was in the
	// state directory (it had no name constraints, was about to expire,
	// or did not cover a domain), or is empty. Clients that trusted the
	// old CA must trust the new one.
	Replaced string
}

// LoadOrCreateCA reads the CA from dir, creating it on first use, and
// replacing one that has no name constraints, expires within 30 days, or
// does not cover one of domains. domains are the DNS names the CA may
// issue for, with their subdomains (default: DefaultDomain); localhost
// and the loopback addresses are always permitted. The private key is
// written with mode 0600.
func LoadOrCreateCA(dir string, domains ...string) (*CA, error) {
	if len(domains) == 0 {
		domains = []string{DefaultDomain}
	}
	domains = caDomains(domains)
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath) // #nosec G304 -- the state directory is the operator's
	keyPEM, keyErr := os.ReadFile(keyPath)    // #nosec G304 -- the state directory is the operator's
	switch {
	case certErr == nil && keyErr == nil:
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		reason := ca.replaceReason(domains, time.Now())
		if reason == "" {
			return ca, nil
		}
		// Keep the domains the old CA covered, so that sandboxes sharing
		// the state directory with other names do not replace it in turn.
		renewed, err := createCA(dir, append(domains, ca.Cert.PermittedDNSDomains...), true)
		if err != nil {
			return nil, err
		}
		renewed.Replaced = reason
		return renewed, nil
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return createCA(dir, domains, false)
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("sandbox: reading CA certificate: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("sandbox: reading CA key: %w", keyErr)
	default:
		return nil, fmt.Errorf("sandbox: %s holds only half of the CA; remove %s and %s to create a new one", dir, CACertFile, caKeyFile)
	}
}

// caDomains returns domains lower case, without duplicates or names
// already covered by another, plus localhost, in order.
func caDomains(domains []string) []string {
	var out []string
	for _, d := range append(domains, "localhost") {
		d = strings.ToLower(strings.Trim(d, "."))
		if d != "" && !permits(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// permits reports whether a name constraint in permitted covers name: the
// name itself or a subdomain of it.
func permits(permitted []string, name string) bool {
	for _, p := range permitted {
		p = strings.ToLower(strings.Trim(p, "."))
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

// replaceReason returns why the CA must be replaced at now, or "".
func (ca *CA) replaceReason(domains []string, now time.Time) string {
	c := ca.Cert
	if !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) == 0 || len(c.PermittedIPRanges) == 0 {
		return "it had no name constraints"
	}
	if c.NotAfter.Sub(now) < caRenewBefore {
		return "it expires on " + c.NotAfter.UTC().Format(time.DateOnly)
	}
	for _, d := range domains {
		if !permits(c.PermittedDNSDomains, d) {
			return "it did not cover " + d
		}
	}
	return ""
}

// loopbackRanges are the addresses the CA may issue for.
func loopbackRanges() []*net.IPNet {
	return []*net.IPNet{
		{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
	}
}

// createCA creates a CA constrained to domains and writes it to dir;
// replace overwrites a CA already there.
func createCA(dir string, domains []string, replace bool) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: creating state directory: %w", err)
	}
	certPEM, keyPEM, err := newCAPEM(caDomains(domains), time.Now(), caValidity)
	if err != nil {
		return nil, err
	}
	write := func(path string, data []byte) error {
		if replace {
			return replaceFile(path, data)
		}
		return os.WriteFile(path, data, 0o600)
	}
	if err := write(filepath.Join(dir, caKeyFile), keyPEM); err != nil {
		return nil, fmt.Errorf("sandbox: writing CA key: %w", err)
	}
	if err := write(filepath.Join(dir, CACertFile), certPEM); err != nil {
		return nil, fmt.Errorf("sandbox: writing CA certificate: %w", err)
	}
	return parseCA(certPEM, keyPEM)
}

// newCAPEM generates a CA key and self-signed certificate valid from now
// for validity, constrained to domains and the loopback addresses (no
// constraints when domains is empty).
func newCAPEM(domains []string, now time.Time, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AAuth Sandbox Development CA", Organization: []string{"AAuth Sandbox"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if len(domains) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = domains
		tmpl.PermittedIPRanges = loopbackRanges()
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox: creating CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox: encoding CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// replaceFile writes data to path with mode 0600 through a temporary file
// renamed into place, so readers see the old file or the new one.
func replaceFile(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() {
		if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
			err = rerr
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("sandbox: CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sandbox: parsing CA certificate: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("sandbox: CA key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sandbox: parsing CA key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("sandbox: CA key cannot sign")
	}
	if pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("sandbox: %s and %s do not belong together; remove both to create a new CA", CACertFile, caKeyFile)
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: signer}, nil
}

// Pool returns a certificate pool holding only the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// IssueServerCert issues a TLS certificate for names, plus localhost and
// the loopback addresses, valid for a year or until the CA expires. The
// names must sit under the CA's domains.
func (ca *CA) IssueServerCert(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sandbox: generating server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	if c := ca.Cert; c.PermittedDNSDomainsCritical {
		for _, n := range names {
			if !permits(c.PermittedDNSDomains, strings.ToLower(n)) {
				return tls.Certificate{}, fmt.Errorf("sandbox: the CA may issue only for %s, not %s", strings.Join(c.PermittedDNSDomains, ", "), n)
			}
		}
	}
	now := time.Now()
	notAfter := now.AddDate(1, 0, 0)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstOr(names, "localhost")},
		DNSNames:     append(append([]string{}, names...), "localhost"),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sandbox: issuing server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sandbox: parsing server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("sandbox: generating serial number: %w", err)
	}
	return n, nil
}

// firstOr returns names[0], or fallback when names is empty (a sandbox that
// serves no roles, only the signing helper).
func firstOr(names []string, fallback string) string {
	if len(names) == 0 {
		return fallback
	}
	return names[0]
}
