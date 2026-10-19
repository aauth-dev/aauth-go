// Command aauth-sandbox runs every AAuth role from aauth-go together for
// development: an agent provider, a person server, an access server and
// two demo resources on https://*.aauth.test, plus a signing helper for
// HTTP clients that cannot sign.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aauth-dev/aauth-go/sandbox"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

// common are the flags every command shares.
type common struct {
	state  string
	domain string
	remote []string
}

func (c *common) add(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.state, "state", "", "state directory for the CA and keys (default ~/.aauth-sandbox)")
	cmd.PersistentFlags().StringVar(&c.domain, "domain", sandbox.DefaultDomain, "parent domain of the role host names")
	cmd.PersistentFlags().StringSliceVar(&c.remote, "remote", nil, "role=https://origin for a role served elsewhere (repeatable)")
}

func (c *common) config() (sandbox.Config, error) {
	cfg := sandbox.Config{StateDir: c.state, Domain: c.domain}
	for _, kv := range c.remote {
		role, u, ok := strings.Cut(kv, "=")
		if !ok {
			return cfg, fmt.Errorf("--remote %q: want role=https://origin", kv)
		}
		if cfg.Remote == nil {
			cfg.Remote = map[string]string{}
		}
		cfg.Remote[role] = u
	}
	return cfg, nil
}

func newRoot() *cobra.Command {
	c := &common{}
	root := &cobra.Command{
		Use:           "aauth-sandbox",
		Short:         "Run every AAuth role locally for development",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	c.add(root)
	root.AddCommand(newServe(c), newCA(c), newHosts(c), newTrace(c))
	return root
}

func newServe(c *common) *cobra.Command {
	var listen, signerAddr, consent, person string
	var noSigner bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the roles on one TLS listener, and the signing helper",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.config()
			if err != nil {
				return err
			}
			cfg.Consent, cfg.Person = consent, person
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			sb, err := sandbox.New(cfg, logger)
			if err != nil {
				return err
			}
			cfg = sb.Config()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listening on %s: %w (port 443 needs no privileges on macOS; on Linux grant CAP_NET_BIND_SERVICE or use a container)", listen, err)
			}
			errs := make(chan error, 2)
			go func() { errs <- sb.Serve(ctx, ln) }()
			if !noSigner {
				go func() { errs <- sb.Signer().ListenAndServe(ctx, signerAddr) }()
			}
			if _, err := sb.Signer().AgentToken(ctx); err != nil {
				logger.Warn("the test agent has no agent token yet", "error", err)
			}
			printBanner(cmd.OutOrStdout(), cfg, ln.Addr().String(), signerAddr, noSigner)
			select {
			case <-ctx.Done():
				return nil
			case err := <-errs:
				return err
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", ":443", "TLS listen address for the roles; identifiers have no port, so clients reach port 443")
	cmd.Flags().StringVar(&signerAddr, "signer", sandbox.DefaultSignerAddr, "signing helper address (loopback only)")
	cmd.Flags().BoolVar(&noSigner, "no-signer", false, "do not run the signing helper")
	cmd.Flags().StringVar(&consent, "consent", sandbox.ConsentAuto, "auto approves every interaction; manual waits for a person or /sandbox/approve")
	cmd.Flags().StringVar(&person, "person", sandbox.DefaultPerson, "the person approvals act for")
	return cmd
}

func printBanner(w io.Writer, cfg sandbox.Config, addr, signerAddr string, noSigner bool) {
	lines := []string{
		"AAuth sandbox: a development tool. Do not expose it or reuse its keys.",
		"",
		"Roles on " + addr + ":",
	}
	for _, r := range sandbox.Roles {
		where := "local"
		if !cfg.Local(r) {
			where = "remote"
		}
		lines = append(lines, fmt.Sprintf("  %-8s %s (%s)", r, cfg.URL(r), where))
	}
	lines = append(lines, "",
		"Hosts entry:  "+cfg.HostsLine(),
		"CA:           "+filepath.Join(cfg.StateDir, sandbox.CACertFile)+" (trust it in Postman: Settings > Certificates)",
		"Consent:      "+cfg.Consent+" as "+cfg.Person,
		"Trace:        "+cfg.URL(sandbox.RolePS)+sandbox.PathTrace)
	if !noSigner {
		lines = append(lines, "Signer:       http://"+signerAddr+"/"+cfg.URL(sandbox.RoleResource)+"/api/documents")
	}
	if _, err := fmt.Fprintln(w, strings.Join(lines, "\n")); err != nil {
		slog.Error("writing banner", "error", err)
	}
}

func newCA(c *common) *cobra.Command {
	ca := &cobra.Command{Use: "ca", Short: "Manage the development certificate authority"}
	ca.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Create the CA if it does not exist, and print its path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			if _, err := sandbox.LoadOrCreateCA(cfg.StateDir); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), filepath.Join(cfg.StateDir, sandbox.CACertFile))
			return err
		},
	})
	ca.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Write the CA certificate (PEM) to standard output",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			authority, err := sandbox.LoadOrCreateCA(cfg.StateDir)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(authority.CertPEM)
			return err
		},
	})
	return ca
}

func (c *common) defaults() (sandbox.Config, error) {
	cfg, err := c.config()
	if err != nil {
		return cfg, err
	}
	return cfg.WithDefaults()
}

func newHosts(c *common) *cobra.Command {
	return &cobra.Command{
		Use:   "hosts",
		Short: "Print the /etc/hosts line for the local role names",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), cfg.HostsLine())
			return err
		},
	}
}

func newTrace(c *common) *cobra.Command {
	var addr string
	var clear bool
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Print (or clear) the running sandbox's message trace",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			authority, err := sandbox.LoadOrCreateCA(cfg.StateDir)
			if err != nil {
				return err
			}
			method := http.MethodGet
			if clear {
				method = http.MethodDelete
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, method, cfg.URL(sandbox.RolePS)+sandbox.PathTrace, nil)
			if err != nil {
				return err
			}
			res, err := sandbox.NewClient(cfg, authority, addr).Do(req)
			if err != nil {
				return fmt.Errorf("is the sandbox running at %s? %w", addr, err)
			}
			defer func() {
				if cerr := res.Body.Close(); cerr != nil {
					slog.Error("closing response", "error", cerr)
				}
			}()
			if res.StatusCode >= 300 {
				return errors.New("trace: " + res.Status)
			}
			if clear {
				return nil
			}
			var v any
			if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:443", "address the sandbox listens on")
	cmd.Flags().BoolVar(&clear, "clear", false, "clear the trace instead of printing it")
	return cmd
}
