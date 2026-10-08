package e2e_test

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// traceEnv turns on an HTTP trace of every call the servers and the agent
// make to each other, so a run's log shows the AAuth exchanges:
//
//	AAUTH_E2E_TRACE=1 go test -v -run TestFourPartyDeployment ./e2e
const traceEnv = "AAUTH_E2E_TRACE"

var traceMu sync.Mutex

// client returns the HTTP client a party uses, named from in the trace. With
// tracing off it is http.DefaultClient.
func (d *deployment) client(from string) *http.Client {
	if os.Getenv(traceEnv) == "" {
		return http.DefaultClient
	}
	return &http.Client{Transport: &tracer{d: d, from: from}}
}

// tracer logs each request and response, naming the parties by role rather
// than by their random test ports.
type tracer struct {
	d    *deployment
	from string
}

func (tr *tracer) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := http.DefaultTransport.RoundTrip(r)
	to, path := tr.d.nameOf(r.URL), r.URL.Path
	switch {
	case err != nil:
		trace("%-9s %s %s%s -> error: %v", tr.from, r.Method, to, path, err)
	default:
		note := ""
		if req := res.Header.Get("AAuth-Requirement"); req != "" {
			note = "  AAuth-Requirement: " + shortenTokens(req)
		}
		if isDiscovery(path) {
			note += "  (discovery)"
		}
		if loc := res.Header.Get("Location"); loc != "" && res.StatusCode == http.StatusAccepted {
			note += "  Location: " + tr.d.pathOf(loc)
		}
		trace("%-9s %s %s%s -> %d%s", tr.from, r.Method, to, path, res.StatusCode, note)
	}
	return res, err
}

// jwtInQuotes matches a quoted compact JWT, such as a resource token in an
// AAuth-Requirement header.
var jwtInQuotes = regexp.MustCompile(`"([A-Za-z0-9_-]{8})[A-Za-z0-9_-]*\.[A-Za-z0-9_.-]+"`)

// shortenTokens keeps the log readable: a token is shown by its first
// characters.
func shortenTokens(s string) string { return jwtInQuotes.ReplaceAllString(s, `"$1…"`) }

// isDiscovery reports whether path is a metadata or key-set fetch, which
// each party makes to learn how to verify or reach another.
func isDiscovery(path string) bool {
	return strings.HasPrefix(path, "/.well-known/") || strings.Contains(path, "jwks")
}

func trace(format string, args ...any) {
	traceMu.Lock()
	defer traceMu.Unlock()
	fmt.Printf("    trace: "+format+"\n", args...)
}

// nameOf names the server a URL reaches by its role in this deployment.
func (d *deployment) nameOf(u *url.URL) string {
	origin := u.Scheme + "://" + u.Host
	switch origin {
	case d.resA.url:
		return "A"
	case d.resB.url:
		return "B"
	case d.psURL:
		if d.asURL == d.psURL {
			return "AP+PS+AS"
		}
		return "AP+PS"
	case d.asURL:
		return "AS"
	}
	return origin
}

func (d *deployment) pathOf(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return d.nameOf(u) + u.Path
}
