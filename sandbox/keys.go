package sandbox

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

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
	created, err := writeExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		return nil, err
	}
	if !created {
		// Another process created the key first; use theirs, so every
		// process sharing the state directory signs with the same key.
		return loadOrCreateKey(dir, name)
	}
	return key, nil
}

// writeExclusive writes data to path only if path does not exist, without
// ever exposing a partly written file: it writes a temporary file and
// links it into place. created is false when path already existed.
func writeExclusive(path string, data []byte) (created bool, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return false, fmt.Errorf("sandbox: writing %s: %w", path, err)
	}
	defer func() {
		if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
			err = fmt.Errorf("sandbox: removing %s: %w", tmp.Name(), rerr)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		closeErr := tmp.Close()
		return false, fmt.Errorf("sandbox: writing %s: %w", path, errors.Join(err, closeErr))
	}
	if err := tmp.Sync(); err != nil {
		closeErr := tmp.Close()
		return false, fmt.Errorf("sandbox: writing %s: %w", path, errors.Join(err, closeErr))
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("sandbox: writing %s: %w", path, err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("sandbox: writing %s: %w", path, err)
	}
	return true, nil
}

// Init creates the certificate authority and every key the sandbox uses
// in cfg's state directory, if they do not exist. Run it once before
// starting several sandbox processes that share a state directory, such as
// one container per role.
func Init(cfg Config) (Config, error) {
	cfg, err := cfg.WithDefaults()
	if err != nil {
		return cfg, err
	}
	if _, err := LoadOrCreateCA(cfg.StateDir); err != nil {
		return cfg, err
	}
	names := make([]string, 0, len(keyAlg))
	for name := range keyAlg {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := loadOrCreateKey(cfg.StateDir, name); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}
