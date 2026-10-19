package sandbox

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	aauth "github.com/aauth-dev/aauth-go"
)

// keyAlg is the algorithm of each role's signing key.
var keyAlg = map[string]string{
	RoleAP:       aauth.AlgEd25519,
	RolePS:       aauth.AlgEd25519,
	RoleAS:       aauth.AlgES256,
	RoleResource: aauth.AlgEd25519,
	RoleDocs:     aauth.AlgEd25519,
	"agent":      aauth.AlgEd25519, // the signing helper's ephemeral key
	"durable":    aauth.AlgEd25519, // the signing helper's durable key
}

// loadOrCreateKey reads <dir>/keys/<name>.pem, generating and saving the
// key on first use, so tokens and thumbprints survive restarts.
func loadOrCreateKey(dir, name string) (crypto.Signer, error) {
	path := filepath.Join(dir, "keys", name+".pem")
	data, err := os.ReadFile(path) // #nosec G304 -- the state directory is the operator's
	if err == nil {
		b, _ := pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("sandbox: %s is not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("sandbox: parsing %s: %w", path, err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("sandbox: %s cannot sign", path)
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("sandbox: reading %s: %w", path, err)
	}
	alg, ok := keyAlg[name]
	if !ok {
		return nil, fmt.Errorf("sandbox: no key algorithm for %q", name)
	}
	key, err := aauth.GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("sandbox: generating %s key: %w", name, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("sandbox: encoding %s key: %w", name, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: creating key directory: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("sandbox: writing %s: %w", path, err)
	}
	return key, nil
}
