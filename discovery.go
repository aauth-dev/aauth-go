package aauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrDisallowedDestination means a discovery fetch was refused because its
// URL was not https or its address was not a public unicast address (see
// [DiscoveryClient]).
var ErrDisallowedDestination = errors.New("aauth: discovery destination not allowed")

// maxDiscoveryRedirects bounds the redirects a discovery fetch follows.
const maxDiscoveryRedirects = 5

// DiscoveryClient returns the http.Client that key and metadata discovery
// use when the caller supplies none: [JWKSResolver] and [FetchMetadata]
// with a nil client, and the server roles without an HTTPClient.
//
// Discovery fetches URLs that a request chooses (a token's iss, a
// signature's id, a metadata document's jwks_uri), so this client only
// reaches public destinations (signature-key §7.3):
//
//   - every request, including each redirect, must be https;
//   - it connects only to public unicast addresses. Loopback, private,
//     link-local, CGNAT, unspecified, multicast, and other special-purpose
//     addresses are refused at dial time, after name resolution, so a DNS
//     answer cannot redirect it to an internal address;
//   - it follows at most five redirects, ignores proxy settings from the
//     environment (a proxy would hide the destination), and gives up after
//     10 seconds.
//
// Refusals wrap [ErrDisallowedDestination]. To reach other destinations,
// such as local servers in development, or to route through an egress
// proxy, supply your own client.
func DiscoveryClient() *http.Client { return defaultDiscoveryClient }

var defaultDiscoveryClient = newDiscoveryClient()

func newDiscoveryClient() *http.Client {
	return newGuardedClient(5*time.Second, 10*time.Second)
}

// EgressClient returns the http.Client that agent-side requests to a person
// server use when the caller supplies none (see [PSClient]). It applies the
// same destination rules as [DiscoveryClient] (https only, public unicast
// addresses only, checked at dial time and on every redirect) but has no
// overall timeout and a longer response-header timeout, because deferred
// requests long-poll with Prefer: wait. Callers bound each request with its
// context.
func EgressClient() *http.Client { return defaultEgressClient }

var defaultEgressClient = newEgressClient()

func newEgressClient() *http.Client {
	return newGuardedClient(5*time.Second, 0)
}

// newGuardedClient builds a client that refuses non-https and non-public
// destinations. total is the overall request timeout; zero means none, in
// which case the response-header timeout is relaxed to allow long polls.
func newGuardedClient(dial, total time.Duration) *http.Client {
	headerTimeout := 5 * time.Second
	if total == 0 {
		headerTimeout = 2 * time.Minute
	}
	dialer := &net.Dialer{Timeout: dial, Control: refuseNonPublic}
	t := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
	}
	return &http.Client{
		Transport: httpsOnly{t},
		Timeout:   total,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxDiscoveryRedirects {
				return fmt.Errorf("%w: more than %d redirects", ErrDisallowedDestination, maxDiscoveryRedirects)
			}
			return nil
		},
	}
}

// httpsOnly refuses any request that is not https, which covers redirects
// as well as the first request.
type httpsOnly struct{ next http.RoundTripper }

func (h httpsOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s is not https", ErrDisallowedDestination, req.URL.Redacted())
	}
	return h.next.RoundTrip(req)
}

// refuseNonPublic is a net.Dialer Control hook: it runs with the resolved
// address of each connection attempt.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDisallowedDestination, address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !isPublicAddr(ip) {
		return fmt.Errorf("%w: %s is not a public address", ErrDisallowedDestination, host)
	}
	return nil
}

// nonPublicPrefixes are special-purpose ranges that IsGlobalUnicast and
// IsPrivate do not exclude.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, which can reach any IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// isPublicAddr reports whether ip is a public unicast address.
func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// discoveryClient returns hc, or the guarded default.
func discoveryClient(hc *http.Client) *http.Client {
	if hc != nil {
		return hc
	}
	return defaultDiscoveryClient
}
