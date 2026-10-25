package sandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// newClient returns the client a role (from) uses for outgoing requests:
// it trusts the sandbox CA as well as the system roots, dials the local
// role host names to the sandbox listener at addr, and tells the
// receiving role who sent the request.
func newClient(from string, cfg Config, ca *CA, addr func() string) *http.Client {
	local := map[string]bool{}
	for _, h := range cfg.LocalHosts() {
		local[h] = true
	}
	// Remote roles are reached through the system roots; local roles
	// through the sandbox CA. A missing system pool (some minimal
	// containers) leaves only the sandbox CA.
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(ca.Cert)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err == nil && local[strings.ToLower(host)] {
				address = addr()
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        50,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: fromHeader{from: from, base: tr}}
}

// fromHeader sets HeaderFrom on every request.
type fromHeader struct {
	from string
	base http.RoundTripper
}

func (f fromHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(HeaderFrom, f.from)
	return f.base.RoundTrip(r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line is already sent, so an encoding failure cannot be
	// reported to the client; the values encoded here are plain structs
	// and maps that always encode.
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // see above
}

func sortedKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NewClient returns a client for a running sandbox listening at addr: it
// trusts the sandbox CA and dials the local role host names at addr, so
// no hosts entries are needed. cfg must have defaults applied.
func NewClient(cfg Config, ca *CA, addr string) *http.Client {
	return newClient("client", cfg, ca, func() string { return addr })
}
