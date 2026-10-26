package sandbox

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
)

// Signing helper control headers. The helper removes them before
// forwarding a request.
const (
	// HeaderPresent selects how the helper signs: agent (default),
	// person, auth, hwk, jkt-jwt, or none.
	HeaderPresent = "X-Sandbox-Present"
	// HeaderToken is the token to present: required for person and
	// auth; for agent it replaces the helper's own agent token.
	HeaderToken = "X-Sandbox-Token"
	// HeaderCapabilitiesOverride replaces the capabilities the helper
	// declares to resources (default: interaction); empty declares none.
	HeaderCapabilitiesOverride = "X-Sandbox-Capabilities"
)

// Presentation modes for HeaderPresent.
const (
	PresentAgent  = "agent"
	PresentPerson = "person"
	PresentAuth   = "auth"
	PresentHWK    = "hwk"
	PresentJKTJWT = "jkt-jwt"
	PresentNone   = "none"
)

// DefaultSignerAddr is the signing helper's default listen address.
const DefaultSignerAddr = "127.0.0.1:8099"

// maxForwardBody bounds a request body the helper forwards.
const maxForwardBody = 4 << 20

// Signer is the sandbox's test agent and its signing helper: HTTP clients
// that cannot sign send requests through it, and it signs them as the
// agent (RFC 9421 with a Signature-Key) and forwards them.
//
// The agent has a durable key and a current (ephemeral) key. It holds an
// agent token from the agent provider bound to the current key, obtained
// by a two-key refresh: a naming JWT signed by the durable key delegating
// to the current key. An agent token a client obtains through the helper
// with jkt-jwt is bound to the same current key, so the client can pass
// it back in X-Sandbox-Token.
type Signer struct {
	sb        *Sandbox
	client    *http.Client
	durable   crypto.Signer
	ephemeral crypto.Signer
	ap        *agentprovider.Client

	mu      sync.Mutex
	token   string
	expires time.Time

	// AnyInterface lets ListenAndServe listen on a non-loopback address.
	// Set it only inside a container whose port is published to the
	// host's loopback address: the helper signs what it is sent.
	AnyInterface bool

	// AnyTarget lets the helper sign and forward requests for any https
	// host. By default it signs only for the sandbox's own role hosts,
	// its upstreams and its remote role origins.
	AnyTarget bool

	// Hosts are extra Host header names the helper answers to, besides
	// localhost and the loopback addresses (and the address it listens
	// on). Requests naming any other host are refused, so a web page
	// cannot reach the helper by pointing a DNS name at 127.0.0.1.
	Hosts []string

	listenHost atomic.Pointer[string] // set by ListenAndServe before serving
}

func (s *Sandbox) newSigner() (*Signer, error) {
	durable, err := loadOrCreateKey(s.cfg.StateDir, "durable")
	if err != nil {
		return nil, err
	}
	ephemeral, err := loadOrCreateKey(s.cfg.StateDir, "agent")
	if err != nil {
		return nil, err
	}
	hc := s.Client("agent")
	// The helper returns redirects to its client unchanged: following one
	// would send the signed request, and its token, to wherever the
	// redirect points, past the checks on the target.
	forward := *hc
	forward.CheckRedirect = noRedirect
	return &Signer{
		sb: s, client: &forward, durable: durable, ephemeral: ephemeral,
		ap: &agentprovider.Client{BaseURL: s.cfg.URL(RoleAP), Paths: agentprovider.Paths{Token: PathEnroll, Refresh: PathAgentToken}, HTTPClient: hc},
	}, nil
}

// AgentToken returns a current agent token, refreshing it at the agent
// provider when it is missing or expires within five minutes.
func (sg *Signer) AgentToken(ctx context.Context) (string, error) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if sg.token != "" && time.Until(sg.expires) > 5*time.Minute {
		return sg.token, nil
	}
	res, err := sg.ap.Refresh(ctx, sg.durable, sg.ephemeral, map[string]string{})
	if err != nil {
		return "", fmt.Errorf("sandbox: agent token from the agent provider: %w", err)
	}
	sg.token, sg.expires = res.AgentToken, time.Now().Add(time.Duration(res.ExpiresIn)*time.Second)
	return sg.token, nil
}

// Sign signs req as the agent. present is one of the Present* modes;
// token is the token to present (required for person and auth). Any
// signature headers already on req are replaced.
func (sg *Signer) Sign(ctx context.Context, req *http.Request, present, token string) error {
	for _, h := range []string{"Signature", "Signature-Input", "Signature-Key", "Content-Digest"} {
		req.Header.Del(h)
	}
	switch present {
	case "", PresentAgent:
		if token == "" {
			t, err := sg.AgentToken(ctx)
			if err != nil {
				return err
			}
			token = t
		}
		aauth.AttachSignatureKey(req, token)
		return aauth.SignRequest(req, sg.ephemeral, "")
	case PresentPerson, PresentAuth:
		if token == "" {
			return fmt.Errorf("sandbox: presenting a %s token needs the token in %s", present, HeaderToken)
		}
		aauth.AttachSignatureKey(req, token)
		return aauth.SignRequest(req, sg.ephemeral, "")
	case PresentHWK:
		return agentprovider.SignHWK(req, sg.ephemeral)
	case PresentJKTJWT:
		naming, err := agentprovider.NewNamingJWT(sg.durable, sg.ephemeral.Public(), 5*time.Minute)
		if err != nil {
			return err
		}
		return agentprovider.SignJKTJWT(req, naming, sg.ephemeral)
	case PresentNone:
		return nil
	default:
		return fmt.Errorf("sandbox: unknown %s %q; use agent, person, auth, hwk, jkt-jwt or none", HeaderPresent, present)
	}
}

// hopHeaders are not forwarded in either direction.
var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Content-Length": true, "Host": true, "Accept-Encoding": true,
}

// ServeHTTP serves the helper:
//
//   - GET / describes the helper and the agent;
//   - POST /sign returns the headers that sign a described request;
//   - any request to /<https URL> is signed and forwarded to that URL,
//     and the response is returned unchanged.
//
// It answers only requests whose Host is a loopback name (or one of
// Hosts), and refuses requests a browser sends on behalf of a web page
// (those with Origin, or Sec-Fetch-Site naming another site). OPTIONS is
// answered without forwarding.
func (sg *Signer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !sg.allowedHost(r.Host) {
		writeJSON(w, http.StatusMisdirectedRequest, map[string]string{
			"error": "the signing helper answers only at localhost or a loopback address, not " + r.Host,
		})
		return
	}
	if fromWebPage(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "the signing helper does not accept requests from web pages (Origin or Sec-Fetch-Site)",
		})
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	target := strings.TrimPrefix(r.RequestURI, "/")
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		sg.serveInfo(w, r)
	case r.URL.Path == "/sign" && r.Method == http.MethodPost:
		sg.serveSign(w, r)
	case strings.HasPrefix(target, "https://"):
		sg.forward(w, r, target)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "send requests to /<https URL>, for example /" + sg.sb.cfg.URL(RoleResource) + "/api/documents",
		})
	}
}

func (sg *Signer) serveInfo(w http.ResponseWriter, r *http.Request) {
	jwk, err := aauth.NewJWK(sg.ephemeral.Public())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	roles := map[string]string{}
	for _, role := range Roles {
		roles[role] = sg.sb.cfg.URL(role)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_key_thumbprint": jwk.Thumbprint(),
		"roles":                roles,
		"usage":                "send a request to /<https URL>; " + HeaderPresent + ": agent|person|auth|hwk|jkt-jwt|none; " + HeaderToken + ": <token>; or, without them, Signature-Key: sig=jwt;jwt=\"<token>\" (or sig=hwk, sig=jkt-jwt)",
		"forward_example":      "http://" + r.Host + "/" + sg.sb.cfg.URL(RoleResource) + "/api/documents",
	})
}

// forward signs r as the agent and sends it to target.
func (sg *Signer) forward(w http.ResponseWriter, r *http.Request, target string) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the target must be an https URL"})
		return
	}
	if !sg.allowedTarget(u) {
		sg.refuseTarget(w, u)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxForwardBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reading the request body: " + err.Error()})
		return
	}
	if len(body) > maxForwardBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return
	}
	out, err := sg.prepare(r.Context(), r.Method, u, r.Header, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	res, err := sg.client.Do(out)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			sg.sb.logf("closing upstream response: %v", cerr)
		}
	}()
	for name, values := range res.Header {
		if hopHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	if _, err := io.Copy(w, res.Body); err != nil {
		sg.sb.logf("copying upstream response: %v", err)
	}
}

// prepare builds the signed outgoing request from a client's request.
func (sg *Signer) prepare(ctx context.Context, method string, u *url.URL, in http.Header, body []byte) (*http.Request, error) {
	caps := declaredCapabilities(in)
	if sg.isRole(u.Hostname(), RolePS) && method == http.MethodPost {
		var err error
		if body, err = addCapabilitiesMember(body, caps); err != nil {
			return nil, err
		}
	}
	var rd io.Reader = http.NoBody
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	out, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	for name, values := range in {
		canon := http.CanonicalHeaderKey(name)
		if hopHeaders[canon] || canon == HeaderPresent || canon == HeaderToken || canon == HeaderCapabilitiesOverride || canon == HeaderFrom {
			continue
		}
		for _, v := range values {
			out.Header.Add(canon, v)
		}
	}
	if err := sg.declareCapabilities(out, caps); err != nil {
		return nil, err
	}
	present, token, err := presentation(in)
	if err != nil {
		return nil, err
	}
	if err := sg.Sign(ctx, out, present, token); err != nil {
		return nil, err
	}
	return out, nil
}

// presentation returns how to sign a forwarded request. X-Sandbox-Present
// and X-Sandbox-Token decide when the client sends either. Otherwise the
// request's own Signature-Key does, as a signing proxy receives it from a
// client that cannot sign (such as a Postman collection generated by
// pidl): the scheme names how to sign, and for the jwt scheme the token
// is presented as the agent, person or auth token its typ names. Without
// a token, or without Signature-Key, the helper presents its own agent
// token.
func presentation(in http.Header) (present, token string, err error) {
	if in.Get(HeaderPresent) != "" || in.Get(HeaderToken) != "" {
		return strings.ToLower(in.Get(HeaderPresent)), in.Get(HeaderToken), nil
	}
	if in.Get(aauth.HeaderSignatureKey) == "" {
		return PresentAgent, "", nil
	}
	sk, err := aauth.ParseSignatureKeyMember(&http.Request{Header: in}, aauth.DefaultSignatureLabel)
	if err != nil {
		return "", "", fmt.Errorf("sandbox: %w", err)
	}
	switch sk.Scheme {
	case aauth.SchemeJWT:
		token = sk.Params["jwt"]
		if token == "" {
			return PresentAgent, "", nil
		}
		typ, err := aauth.TokenType(token)
		if err != nil {
			return "", "", fmt.Errorf("sandbox: Signature-Key token: %w", err)
		}
		switch typ {
		case aauth.TypAgent:
			return PresentAgent, token, nil
		case aauth.TypPerson:
			return PresentPerson, token, nil
		case aauth.TypAuth:
			return PresentAuth, token, nil
		default:
			return "", "", fmt.Errorf("sandbox: Signature-Key token has typ %q; present an agent, person or auth token", typ)
		}
	case PresentHWK, PresentJKTJWT:
		return sk.Scheme, "", nil
	default:
		return "", "", fmt.Errorf("sandbox: Signature-Key scheme %q; use jwt, hwk or jkt-jwt", sk.Scheme)
	}
}

// declaredCapabilities returns the capabilities the test agent declares:
// interaction, or the client's X-Sandbox-Capabilities (empty for none).
func declaredCapabilities(in http.Header) []string {
	if v, ok := in[http.CanonicalHeaderKey(HeaderCapabilitiesOverride)]; ok {
		return strings.FieldsFunc(strings.Join(v, ","), func(r rune) bool { return r == ',' || r == ' ' })
	}
	return []string{aauth.CapabilityInteraction}
}

// declareCapabilities adds AAuth-Capabilities to requests for local
// resources when the client did not: the test agent can bring the person
// to an interaction (draft-11 §11.7).
func (sg *Signer) declareCapabilities(out *http.Request, caps []string) error {
	if out.Header.Get(aauth.HeaderCapabilities) != "" || len(caps) == 0 {
		return nil
	}
	if !sg.isRole(out.URL.Hostname(), RoleResource) && !sg.isRole(out.URL.Hostname(), RoleDocs) {
		return nil
	}
	v, err := aauth.FormatCapabilities(caps)
	if err != nil {
		return err
	}
	out.Header.Set(aauth.HeaderCapabilities, v)
	return nil
}

// addCapabilitiesMember adds "capabilities" to a JSON object body that
// lacks it, keeping the members already written in their order. Person
// server endpoints take capabilities in the body (draft-11 §7.1, §7.2).
func addCapabilitiesMember(body []byte, caps []string) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(caps) == 0 || len(trimmed) < 2 || trimmed[0] != '{' {
		return body, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return body, nil //nolint:nilerr // not a JSON object: forwarded unchanged
	}
	if _, ok := members["capabilities"]; ok {
		return body, nil
	}
	value, err := json.Marshal(caps)
	if err != nil {
		return nil, err
	}
	inner := bytes.TrimSpace(trimmed[1 : len(trimmed)-1])
	out := []byte{'{'}
	if len(inner) > 0 {
		out = append(append(out, inner...), ',')
	}
	out = append(append(append(out, `"capabilities":`...), value...), '}')
	return out, nil
}

// allowedHost reports whether the helper answers a request whose Host
// header is hostport: localhost, a loopback address, the address the
// helper listens on, or one of Hosts.
func (sg *Signer) allowedHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if lh := sg.listenHost.Load(); lh != nil && host == *lh {
		return true
	}
	for _, h := range sg.Hosts {
		if strings.EqualFold(strings.TrimSuffix(h, "."), host) {
			return true
		}
	}
	return false
}

// fromWebPage reports whether a browser sent r on behalf of a web page:
// browsers send Origin with cross-origin and state-changing requests, and
// Sec-Fetch-Site on every request. Clients such as curl, Postman and
// Newman send neither.
func fromWebPage(r *http.Request) bool {
	if _, ok := r.Header["Origin"]; ok {
		return true
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return true
	}
	return false
}

// allowedTarget reports whether the helper signs for u: one of the
// sandbox's role origins (local or remote) or upstream hosts, unless
// AnyTarget is set.
func (sg *Signer) allowedTarget(u *url.URL) bool {
	if sg.AnyTarget {
		return true
	}
	want := originKey(u)
	for _, role := range Roles {
		if ru, err := url.Parse(sg.sb.cfg.URL(role)); err == nil && originKey(ru) == want {
			return true
		}
	}
	for _, h := range sg.sb.cfg.UpstreamHosts() {
		if want == h+":443" {
			return true
		}
	}
	return false
}

func (sg *Signer) refuseTarget(w http.ResponseWriter, u *url.URL) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "the signing helper signs only for the sandbox's own hosts, not " + u.Host + "; serve it with --signer-any-target to sign for any host",
	})
}

// originKey is an https URL's host and port, lower case, with the
// default port made explicit.
func originKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func (sg *Signer) isRole(host, role string) bool {
	u, err := url.Parse(sg.sb.cfg.URL(role))
	return err == nil && strings.EqualFold(u.Hostname(), host)
}

// signRequest is the body of POST /sign.
type signRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body"`
	Present string      `json:"present"`
	Token   string      `json:"token"`
}

// serveSign answers POST /sign with the headers that sign the request
// the body describes, for clients that send requests themselves.
func (sg *Signer) serveSign(w http.ResponseWriter, r *http.Request) {
	var in signRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxForwardBody)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decoding the request: " + err.Error()})
		return
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be an https URL"})
		return
	}
	if !sg.allowedTarget(u) {
		sg.refuseTarget(w, u)
		return
	}
	h := http.Header{}
	for _, kv := range in.Headers {
		h.Add(kv[0], kv[1])
	}
	if in.Present != "" {
		h.Set(HeaderPresent, in.Present)
	}
	if in.Token != "" {
		h.Set(HeaderToken, in.Token)
	}
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	out, err := sg.prepare(r.Context(), method, u, h, []byte(in.Body))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var add [][2]string
	for _, name := range []string{aauth.HeaderCapabilities, "Content-Digest", "Signature-Key", "Signature-Input", "Signature"} {
		if v := out.Header.Get(name); v != "" {
			add = append(add, [2]string{name, v})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"headers": add})
}

// ListenAndServe serves the helper on addr, which must be a loopback
// address unless AnyInterface is set: the helper signs anything it is
// sent.
func (sg *Signer) ListenAndServe(ctx context.Context, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("sandbox: signer address: %w", err)
	}
	if !sg.AnyInterface && !IsLoopback(addr) {
		return fmt.Errorf("sandbox: the signing helper listens on loopback only, not %q", addr)
	}
	if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
		lh := strings.ToLower(strings.Trim(host, "[]"))
		sg.listenHost.Store(&lh)
	}
	srv := &http.Server{Addr: addr, Handler: sg, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			sg.sb.logf("closing the signing helper: %v", err)
		}
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
