package sandbox

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestLoadOrCreateKeyConcurrent checks that processes sharing a state
// directory all end up with the same key when they start together.
func TestLoadOrCreateKeyConcurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	ders := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k, err := loadOrCreateKey(dir, "durable")
			if err != nil {
				errs[i] = err
				return
			}
			ders[i], errs[i] = x509.MarshalPKIXPublicKey(k.Public())
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if string(ders[i]) != string(ders[0]) {
			t.Fatal("concurrent callers got different keys")
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("keys directory has %d entries, want only durable.pem (no leftover temporary files)", len(entries))
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Init(Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != dir {
		t.Fatalf("state dir = %q", cfg.StateDir)
	}
	if _, err := os.Stat(filepath.Join(dir, CACertFile)); err != nil {
		t.Fatal(err)
	}
	for name := range keyAlg {
		if _, err := os.Stat(filepath.Join(dir, "keys", name+".pem")); err != nil {
			t.Errorf("key %s: %v", name, err)
		}
	}
	// Init is idempotent.
	if _, err := Init(Config{StateDir: dir}); err != nil {
		t.Fatal(err)
	}
}

func TestIssueServerCertNoNames(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueServerCert(nil); err != nil {
		t.Fatalf("a sandbox serving no roles needs a certificate too: %v", err)
	}
}
