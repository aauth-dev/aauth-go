package sandbox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
)

// Sandbox runs the local roles behind one TLS listener, routed by host.
type Sandbox struct {
	cfg    Config
	ca     *CA
	cert   tls.Certificate
	trace  *Trace
	logger *slog.Logger

	addrMu sync.RWMutex
	addr   string

	clientsMu sync.Mutex
	clients   map[string]*http.Client

	approving sync.Map // PS pending IDs being approved automatically

	ap     *agentprovider.Server
	ps     *personserver.Server
	as     *accessserver.Server
	res    map[string]*resource
	signer *Signer
	routes map[string]http.Handler // by host
}

// New builds a sandbox: it loads or creates the CA and role keys in
// cfg.StateDir and configures every local role. Call Serve to start it.
func New(cfg Config, logger *slog.Logger) (*Sandbox, error) {
	home, err := os.UserHomeDir()
	if err != nil && cfg.StateDir == "" {
		return nil, fmt.Errorf("sandbox: no state directory and no home directory: %w", err)
	}
	cfg, err = cfg.withDefaults(home)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	ca, err := LoadOrCreateCA(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	cert, err := ca.IssueServerCert(cfg.LocalHosts())
	if err != nil {
		return nil, err
	}
	s := &Sandbox{
		cfg: cfg, ca: ca, cert: cert, trace: NewTrace(cfg.TraceSize), logger: logger,
		addr: "127.0.0.1:443", clients: map[string]*http.Client{}, res: map[string]*resource{}, routes: map[string]http.Handler{},
	}
	if err := s.build(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sandbox) build() error {
	if s.cfg.Local(RoleAP) {
		ap, err := s.newAgentProvider()
		if err != nil {
			return fmt.Errorf("sandbox: agent provider: %w", err)
		}
		s.ap = ap
		s.route(RoleAP, ap)
	}
	if s.cfg.Local(RolePS) {
		ps, err := s.newPersonServer()
		if err != nil {
			return fmt.Errorf("sandbox: person server: %w", err)
		}
		s.ps = ps
		mux := http.NewServeMux()
		mux.HandleFunc(PathInteraction, s.servePSInteraction)
		mux.HandleFunc(PathApprove, s.servePSApprove)
		mux.Handle("/", ps)
		s.route(RolePS, mux)
	}
	if s.cfg.Local(RoleAS) {
		as, err := s.newAccessServer()
		if err != nil {
			return fmt.Errorf("sandbox: access server: %w", err)
		}
		s.as = as
		s.route(RoleAS, as)
	}
	for role, audience := range map[string]string{RoleResource: s.cfg.URL(RolePS), RoleDocs: s.cfg.URL(RoleAS)} {
		if !s.cfg.Local(role) {
			continue
		}
		r, err := s.newResource(role, audience)
		if err != nil {
			return fmt.Errorf("sandbox: %s: %w", role, err)
		}
		s.res[role] = r
		s.route(role, r)
	}
	for _, host := range s.cfg.UpstreamHosts() {
		if err := s.routeUpstream(host, s.cfg.Upstreams[host]); err != nil {
			return err
		}
	}
	signer, err := s.newSigner()
	if err != nil {
		return fmt.Errorf("sandbox: signing helper: %w", err)
	}
	s.signer = signer
	return nil
}

// route serves role's handler on its host, recording its traffic and
// making Location headers absolute, as the draft's examples show them.
func (s *Sandbox) route(role string, h http.Handler) {
	s.routes[s.cfg.Hosts[role]] = s.trace.record(role, absoluteLocation(s.cfg.URL(role), h))
}

// routeUpstream serves host by passing requests to the server at origin,
// keeping the Host header: the server's identifier is https://<host>, and
// AAuth signatures cover @authority. The trace names it by host.
func (s *Sandbox) routeUpstream(host, origin string) error {
	target, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("sandbox: upstream %s: %w", host, err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		FlushInterval: -1, // long-polled responses pass through as written
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.logf("upstream %s at %s: %v", host, origin, err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream " + host + " at " + origin + " is not reachable"})
		},
	}
	s.routes[host] = s.trace.record(host, proxy)
	return nil
}

// absoluteLocation resolves a relative Location against origin before the
// response is written, so clients can follow it without knowing which
// server answered.
func absoluteLocation(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&locationWriter{ResponseWriter: w, origin: origin}, r)
	})
}

type locationWriter struct {
	http.ResponseWriter
	origin string
	done   bool
}

func (l *locationWriter) fix() {
	if l.done {
		return
	}
	l.done = true
	if loc := l.Header().Get("Location"); strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
		l.Header().Set("Location", l.origin+loc)
	}
}

func (l *locationWriter) WriteHeader(code int) {
	l.fix()
	l.ResponseWriter.WriteHeader(code)
}

func (l *locationWriter) Write(b []byte) (int, error) {
	l.fix()
	return l.ResponseWriter.Write(b)
}

// Flush passes flushes through, for long-polled responses.
func (l *locationWriter) Flush() {
	l.fix()
	if f, ok := l.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Config returns the configuration with defaults applied.
func (s *Sandbox) Config() Config { return s.cfg }

// CA returns the sandbox certificate authority.
func (s *Sandbox) CA() *CA { return s.ca }

// Trace returns the message trace.
func (s *Sandbox) Trace() *Trace { return s.trace }

// Signer returns the test agent and signing helper.
func (s *Sandbox) Signer() *Signer { return s.signer }

// SetAddr sets the address that local role host names are dialed at;
// Serve sets it from its listener.
func (s *Sandbox) SetAddr(addr string) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
	}
	s.addrMu.Lock()
	s.addr = addr
	s.addrMu.Unlock()
}

func (s *Sandbox) currentAddr() string {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	return s.addr
}

// Client returns the HTTP client a role (or "agent") sends requests
// with: it trusts the sandbox CA and reaches local roles by name.
func (s *Sandbox) Client(from string) *http.Client {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if c, ok := s.clients[from]; ok {
		return c
	}
	c := newClient(from, s.cfg, s.ca, s.currentAddr)
	s.clients[from] = c
	return c
}

// Handler routes requests to local roles by host, and serves the trace
// on every role host.
func (s *Sandbox) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		h, ok := s.routes[host]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown host " + host, "hosts": s.cfg.LocalHosts()})
			return
		}
		if r.URL.Path == PathTrace {
			s.trace.serveHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// TLSConfig returns the listener's TLS configuration.
func (s *Sandbox) TLSConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
}

// Serve serves the roles on ln over TLS until ctx ends.
func (s *Sandbox) Serve(ctx context.Context, ln net.Listener) error {
	s.SetAddr(ln.Addr().String())
	srv := &http.Server{
		Handler: s.Handler(), TLSConfig: s.TLSConfig(), ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: slog.NewLogLogger(s.logger.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			s.logf("closing the sandbox listener: %v", err)
		}
	}()
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Sandbox) logf(format string, args ...any) {
	s.logger.Warn(fmt.Sprintf(format, args...))
}

// servePSInteraction is the person server's interaction page.
func (s *Sandbox) servePSInteraction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderPage(w, http.StatusOK, pageData{Title: "Approve agent access", Text: "An agent asks for access on your behalf.", Code: r.URL.Query().Get("code"), Person: s.cfg.Person})
	case http.MethodPost:
		if err := s.approvePS(r.Context(), r.FormValue("code")); err != nil {
			renderPage(w, http.StatusBadRequest, pageData{Title: "Not approved", Text: err.Error()})
			return
		}
		renderPage(w, http.StatusOK, pageData{Title: "Approved", Text: "You can return to your agent."})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// servePSApprove is the person server's headless approval endpoint.
func (s *Sandbox) servePSApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.approvePS(r.Context(), r.URL.Query().Get("code")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "person": s.cfg.Person})
}
