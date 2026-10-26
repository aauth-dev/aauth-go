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
	"slices"
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
	state    string
	domain   string
	remote   []string
	roles    []string
	upstream []string
}

func (c *common) add(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.state, "state", "", "state directory for the CA and keys (default ~/.aauth-sandbox)")
	cmd.PersistentFlags().StringVar(&c.domain, "domain", sandbox.DefaultDomain, "parent domain of the role host names")
	cmd.PersistentFlags().StringSliceVar(&c.remote, "remote", nil, "role=https://origin for a role served elsewhere (repeatable)")
	cmd.PersistentFlags().StringSliceVar(&c.upstream, "upstream", nil, "host=http://origin for a server of your own that the sandbox fronts at https://<host>, such as petstore=http://127.0.0.1:8080 (repeatable; a name without a dot is under --domain)")
	cmd.PersistentFlags().StringSliceVar(&c.roles, "roles", nil, "roles to serve here, such as ps or ap,ps; the others are reached at their usual https://<role>.<domain> (none: serve no roles, for a signing helper on its own)")
}

func (c *common) config() (sandbox.Config, error) {
	cfg := sandbox.Config{StateDir: c.state, Domain: c.domain}
	if len(c.roles) > 0 {
		local := map[string]bool{}
		for _, r := range c.roles {
			if r == "none" {
				continue
			}
			if !slices.Contains(sandbox.Roles, r) {
				return cfg, fmt.Errorf("--roles: unknown role %q (want %s or none)", r, strings.Join(sandbox.Roles, ", "))
			}
			local[r] = true
		}
		domain := c.domain
		if domain == "" {
			domain = sandbox.DefaultDomain
		}
		cfg.Remote = map[string]string{}
		for _, r := range sandbox.Roles {
			if !local[r] {
				cfg.Remote[r] = "https://" + r + "." + domain
			}
		}
	}
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
	for _, kv := range c.upstream {
		host, u, ok := strings.Cut(kv, "=")
		if !ok {
			return cfg, fmt.Errorf("--upstream %q: want host=http://origin", kv)
		}
		if cfg.Upstreams == nil {
			cfg.Upstreams = map[string]string{}
		}
		cfg.Upstreams[host] = u
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
	root.AddCommand(newServe(c), newInit(c), newCA(c), newHosts(c), newTrace(c), newHealth(c))
	return root
}

func newServe(c *common) *cobra.Command {
	var listen, signerAddr, consent, person string
	var noSigner, listenAnyInterface, signerAnyInterface, signerAnyTarget bool
	var signerHosts []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the roles on one TLS listener, and the signing helper",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !listenAnyInterface && !sandbox.IsLoopback(listen) {
				return fmt.Errorf("--listen %s is not a loopback address: the roles hand out tokens and approve consent automatically; pass --listen-any-interface to listen there anyway (inside a container)", listen)
			}
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

			errs := make(chan error, 2)
			addr := "(no roles served here)"
			if len(cfg.LocalHosts()) > 0 {
				ln, err := net.Listen("tcp", listen)
				if err != nil {
					return fmt.Errorf("listening on %s: %w (port 443 needs no privileges on macOS; on Linux grant CAP_NET_BIND_SERVICE or use a container)", listen, err)
				}
				addr = ln.Addr().String()
				// Record the address before serving: the agent token request
				// below dials the roles through it.
				sb.SetAddr(addr)
				go func() { errs <- sb.Serve(ctx, ln) }()
			} else if noSigner {
				return errors.New("nothing to serve: --roles none needs the signing helper")
			}
			if !noSigner {
				sb.Signer().AnyInterface = signerAnyInterface
				sb.Signer().AnyTarget = signerAnyTarget
				sb.Signer().Hosts = signerHosts
				go func() { errs <- sb.Signer().ListenAndServe(ctx, signerAddr) }()
			}
			if _, err := sb.Signer().AgentToken(ctx); err != nil {
				logger.Warn("the test agent has no agent token yet", "error", err)
			}
			printBanner(cmd.OutOrStdout(), cfg, addr, signerAddr, noSigner)
			select {
			case <-ctx.Done():
				return nil
			case err := <-errs:
				return err
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", sandbox.DefaultListenAddr, "TLS listen address for the roles (loopback only); identifiers have no port, so clients reach port 443")
	cmd.Flags().BoolVar(&listenAnyInterface, "listen-any-interface", false, "let the roles listen on a non-loopback address; only inside a container whose port is published to the host's loopback address")
	cmd.Flags().StringVar(&signerAddr, "signer", sandbox.DefaultSignerAddr, "signing helper address (loopback only)")
	cmd.Flags().BoolVar(&noSigner, "no-signer", false, "do not run the signing helper")
	cmd.Flags().BoolVar(&signerAnyInterface, "signer-any-interface", false, "let the signing helper listen on a non-loopback address; only inside a container whose port is published to the host's loopback address")
	cmd.Flags().BoolVar(&signerAnyTarget, "signer-any-target", false, "let the signing helper sign for any https host, not only the sandbox's roles, upstreams and remote origins")
	cmd.Flags().StringSliceVar(&signerHosts, "signer-host", nil, "extra Host name the signing helper answers to, besides localhost and loopback addresses (repeatable)")
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
	for _, h := range cfg.UpstreamHosts() {
		lines = append(lines, fmt.Sprintf("  %-8s https://%s (upstream %s)", strings.SplitN(h, ".", 2)[0], h, cfg.Upstreams[h]))
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
			if _, err := loadCA(cmd, cfg); err != nil {
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
			authority, err := loadCA(cmd, cfg)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(authority.CertPEM)
			return err
		},
	})
	return ca
}

// loadCA loads or creates the CA for cfg, telling the user when an old CA
// was replaced and must be trusted again.
func loadCA(cmd *cobra.Command, cfg sandbox.Config) (*sandbox.CA, error) {
	authority, err := sandbox.LoadOrCreateCA(cfg.StateDir, cfg.CADomains()...)
	if err != nil {
		return nil, err
	}
	if authority.Replaced != "" {
		msg := "created a new sandbox CA because " + authority.Replaced + "; trust the new " +
			filepath.Join(cfg.StateDir, sandbox.CACertFile) + " where you trusted the old one"
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), msg); err != nil {
			return nil, err
		}
	}
	return authority, nil
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
			authority, err := loadCA(cmd, cfg)
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

func newInit(c *common) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the CA and every key in the state directory, once, before starting several sandbox processes that share it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			if _, err := loadCA(cmd, cfg); err != nil {
				return err
			}
			cfg, err = sandbox.Init(cfg)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "initialized "+cfg.StateDir)
			return err
		},
	}
}

// newHealth checks the roles this process serves (each answers its trace
// endpoint) and, with --signer, the signing helper. It needs no shell or
// curl, so container images without them can use it as a health check.
func newHealth(c *common) *cobra.Command {
	var addr, signer string
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Exit 0 when the local roles, and the signing helper if given, answer",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.defaults()
			if err != nil {
				return err
			}
			authority, err := loadCA(cmd, cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			client := sandbox.NewClient(cfg, authority, addr)
			for _, r := range sandbox.Roles {
				if !cfg.Local(r) {
					continue
				}
				if err := healthGet(ctx, client, cfg.URL(r)+sandbox.PathTrace, nil); err != nil {
					return fmt.Errorf("%s: %w", r, err)
				}
			}
			if signer != "" {
				h := http.Header{"X-Sandbox-Present": {"none"}}
				if err := healthGet(ctx, http.DefaultClient, "http://"+signer+"/"+cfg.URL(sandbox.RolePS)+sandbox.PathTrace, h); err != nil {
					return fmt.Errorf("signing helper: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:443", "address the local roles listen on")
	cmd.Flags().StringVar(&signer, "signer", "", "signing helper address to check, such as 127.0.0.1:8099")
	return cmd
}

func healthGet(ctx context.Context, client *http.Client, url string, h http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	if cerr := res.Body.Close(); cerr != nil {
		return cerr
	}
	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status)
	}
	return nil
}
