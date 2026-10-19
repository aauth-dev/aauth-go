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
	"time"
)

// CA file names in the state directory.
const (
	CACertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"
)

// CA is the sandbox's development certificate authority.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// LoadOrCreateCA reads the CA from dir, creating it on first use. The
// private key is written with mode 0600.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath) // #nosec G304 -- the state directory is the operator's
	keyPEM, keyErr := os.ReadFile(keyPath)    // #nosec G304 -- the state directory is the operator's
	switch {
	case certErr == nil && keyErr == nil:
		return parseCA(certPEM, keyPEM)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return createCA(dir)
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("sandbox: reading CA certificate: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("sandbox: reading CA key: %w", keyErr)
	default:
		return nil, fmt.Errorf("sandbox: %s holds only half of the CA; remove %s and %s to create a new one", dir, CACertFile, caKeyFile)
	}
}

func createCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: creating state directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sandbox: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AAuth Sandbox Development CA", Organization: []string{"AAuth Sandbox"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sandbox: creating CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("sandbox: encoding CA key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("sandbox: writing CA key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, CACertFile), certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("sandbox: writing CA certificate: %w", err)
	}
	return parseCA(certPEM, keyPEM)
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
	return &CA{Cert: cert, CertPEM: certPEM, key: signer}, nil
}

// Pool returns a certificate pool holding only the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// IssueServerCert issues a TLS certificate for names, plus localhost and
// the loopback addresses, valid for a year.
func (ca *CA) IssueServerCert(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sandbox: generating server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     append(append([]string{}, names...), "localhost"),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
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
