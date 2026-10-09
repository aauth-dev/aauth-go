package e2e_test

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// traceEnv turns on an HTTP trace of the calls the servers and the agent make
// to each other, so a run's log shows the AAuth exchanges:
//
//	AAUTH_E2E_TRACE=1 go test -v -run TestFourPartyDeployment ./e2e
//
// Level 1 shows the protocol calls: tokens, challenges, federation, and
// revocation. Level 2 adds the metadata and key-set fetches each party makes
// to learn how to verify or reach another (discovery), which are about half
// of all requests.
const traceEnv = "AAUTH_E2E_TRACE"

// traceLevel reads the level from the environment: 0 is off, and any value
// that is not a number counts as 1.
func traceLevel() int {
	v := os.Getenv(traceEnv)
	if v == "" || v == "0" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return n
	}
	return 1
}

var (
	traceMu  sync.Mutex
	traceSeq atomic.Int64
)

// client returns the HTTP client a party uses, named from in the trace. With
// tracing off it is http.DefaultClient.
func (d *deployment) client(from string) *http.Client {
	level := traceLevel()
	if level == 0 {
		return http.DefaultClient
	}
	return &http.Client{Transport: &tracer{d: d, from: from, discovery: level >= 2}}
}

// tracer logs each protocol request when it starts and its response when it
// returns, under a shared number. A request made while handling another (the
// PS calling the AS while answering the agent) starts and ends between the
// outer one's two lines, so the nesting is visible. Parties are named by role
// rather than by their random test ports.
type tracer struct {
	d         *deployment
	from      string
	discovery bool // also log metadata and key-set fetches
}

func (tr *tracer) RoundTrip(r *http.Request) (*http.Response, error) {
	to, path := tr.d.nameOf(r.URL), r.URL.Path
	quiet := isDiscovery(path) && !tr.discovery
	var id int64
	if !quiet {
		id = traceSeq.Add(1)
		note := ""
		if isDiscovery(path) {
			note = "  (discovery)"
		}
		trace("#%-3d %-9s %s %s%s%s", id, tr.from, r.Method, to, path, note)
	}
	res, err := http.DefaultTransport.RoundTrip(r)
	if quiet {
		return res, err
	}
	if err != nil {
		trace("#%-3d %-9s -> error: %v", id, "", err)
		return res, err
	}
	note := ""
	if req := res.Header.Get("AAuth-Requirement"); req != "" {
		note = "  AAuth-Requirement: " + shortenTokens(req)
	}
	if loc := res.Header.Get("Location"); loc != "" && res.StatusCode == http.StatusAccepted {
		note += "  Location: " + tr.d.pathOf(loc)
	}
	trace("#%-3d %-9s -> %d%s", id, "", res.StatusCode, note)
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
