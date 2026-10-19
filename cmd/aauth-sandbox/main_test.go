package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/aauth-dev/aauth-go/sandbox"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestHostsAndCA(t *testing.T) {
	state := t.TempDir()
	out, err := run(t, "hosts", "--state", state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "127.0.0.1 ap.aauth.test ps.aauth.test as.aauth.test resource.aauth.test docs.aauth.test" {
		t.Errorf("hosts %q", out)
	}
	out, err = run(t, "hosts", "--state", state, "--remote", "ps=https://ps.example.com")
	if err != nil || strings.Contains(out, "ps.aauth.test") {
		t.Errorf("hosts with a remote PS %q, %v", out, err)
	}
	if _, err := run(t, "hosts", "--remote", "ps"); err == nil {
		t.Error("malformed --remote accepted")
	}
	path, err := run(t, "ca", "init", "--state", state)
	if err != nil || !strings.HasSuffix(strings.TrimSpace(path), sandbox.CACertFile) {
		t.Fatalf("ca init %q, %v", path, err)
	}
	pem, err := run(t, "ca", "export", "--state", state)
	if err != nil || !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("ca export %q, %v", pem, err)
	}
}

func TestTrace(t *testing.T) {
	state := t.TempDir()
	sb, err := sandbox.New(sandbox.Config{StateDir: state}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sb.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, err := sb.Signer().AgentToken(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "trace", "--state", state, "--addr", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"to": "ap"`) {
		t.Fatalf("trace %s", out)
	}
	if _, err := run(t, "trace", "--state", state, "--addr", ln.Addr().String(), "--clear"); err != nil {
		t.Fatal(err)
	}
	if n := len(sb.Trace().Exchanges()); n != 0 {
		t.Fatalf("%d exchanges after clear", n)
	}
}

func TestRolesFlag(t *testing.T) {
	c := &common{domain: "aauth.test", roles: []string{"ps"}}
	cfg, err := c.config()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Remote["ps"]; ok {
		t.Fatal("ps should be local")
	}
	if cfg.Remote["as"] != "https://as.aauth.test" || len(cfg.Remote) != 4 {
		t.Fatalf("remote = %v", cfg.Remote)
	}

	c = &common{roles: []string{"none"}, remote: []string{"ps=https://ps.example.com"}}
	cfg, err = c.config()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Remote) != 5 || cfg.Remote["ps"] != "https://ps.example.com" || cfg.Remote["ap"] != "https://ap.aauth.test" {
		t.Fatalf("remote = %v (--remote should override the default)", cfg.Remote)
	}

	if _, err := (&common{roles: []string{"nope"}}).config(); err == nil {
		t.Fatal("unknown role accepted")
	}
}
