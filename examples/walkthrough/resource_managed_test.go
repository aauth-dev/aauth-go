package walkthrough_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/interactioncode"
)

// approvalRequest is a pending interaction at the resource.
type approvalRequest struct {
	code     string
	agentJKT string // the agent that asked, by key thumbprint
	session  string // the session token, once the person approves
}

// ledger is a resource that manages authorization itself (two-party): it
// asks the person directly, then issues an AAuth-Access session token.
type ledger struct {
	url      string
	resolver aauth.KeyResolver

	mu       sync.Mutex
	pending  map[string]*approvalRequest // by pending ID
	sessions map[string]string           // session token → agent key thumbprint
}

func newLedger(t *testing.T, w *world) *ledger {
	t.Helper()
	l := &ledger{resolver: aauth.NewJWKSResolver(w.hc), pending: map[string]*approvalRequest{}, sessions: map[string]string{}}
	l.url = serve(t, l)
	return l
}

func (l *ledger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/interact":
		l.interactionPage(w, r)
	case strings.HasPrefix(r.URL.Path, "/pending/"):
		l.servePending(w, r)
	default:
		l.serveAPI(w, r)
	}
}

func (l *ledger) serveAPI(w http.ResponseWriter, r *http.Request) {
	// pidl:begin resource-managed.request.resource
	agent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: l.resolver})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	// A request carrying a session token this resource issued is served;
	// any other asks the person first.
	if session := r.Header.Get(aauth.HeaderAAuthAccess); session != "" {
		l.serveSession(w, session, agent)
		return
	}
	l.requireInteraction(w, r, agent)
	// pidl:end resource-managed.request.resource
}

func (l *ledger) requireInteraction(w http.ResponseWriter, r *http.Request, agent *aauth.AgentClaims) {
	// pidl:begin resource-managed.interaction-required.resource
	// Only an agent that declared the interaction capability can bring
	// the person here.
	if !aauth.CanRaise(r, aauth.RequirementInteraction) {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.TokenErrUserUnreachable, "the person must approve this agent")
		return
	}
	code, err := interactioncode.Generate()
	if err != nil {
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	id := randomToken()
	l.mu.Lock()
	l.pending[id] = &approvalRequest{code: code, agentJKT: agent.Cnf.JWK.Thumbprint()}
	l.mu.Unlock()
	// 202 with Location to poll, and the URL and code for the person.
	aauth.ChainInteraction(w, l.url+"/pending/"+id, l.url+"/interact", code)
	// pidl:end resource-managed.interaction-required.resource
}

func (l *ledger) interactionPage(w http.ResponseWriter, r *http.Request) {
	// pidl:begin resource-managed.complete-interaction.resource
	code, err := interactioncode.Canonicalize(r.URL.Query().Get("code"))
	person, signedIn := signedInPerson(r) // the resource's own login
	if err != nil || !signedIn {
		http.Error(w, "sign in and use the code your agent showed you", http.StatusBadRequest)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range l.pending {
		if c, err := interactioncode.Canonicalize(p.code); err == nil && c == code && p.session == "" {
			// The person approved: the session belongs to this agent's key.
			p.session = randomToken()
			l.sessions[p.session] = p.agentJKT
			respondJSON(w, map[string]string{"approved_by": person})
			return
		}
	}
	http.Error(w, "unknown or used code", http.StatusBadRequest)
	// pidl:end resource-managed.complete-interaction.resource
}

func (l *ledger) servePending(w http.ResponseWriter, r *http.Request) {
	// pidl:begin resource-managed.poll.resource
	agent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: l.resolver})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	l.mu.Lock()
	p := l.pending[strings.TrimPrefix(r.URL.Path, "/pending/")]
	l.mu.Unlock()
	if p == nil || p.agentJKT != agent.Cnf.JWK.Thumbprint() {
		aauth.WriteProblem(w, http.StatusNotFound, aauth.ErrCodeInvalidRequest, "no such request")
		return
	}
	if p.session == "" { // still waiting for the person
		w.Header().Set(aauth.HeaderLocation, l.url+r.URL.Path)
		w.Header().Set(aauth.HeaderRetryAfter, "1")
		w.WriteHeader(http.StatusAccepted)
		respondJSON(w, aauth.PendingStatus{Status: "pending"})
		return
	}
	// pidl:begin resource-managed.session-token.resource
	// Approved: answer the poll with the session token in AAuth-Access.
	aauth.WriteAuthorized(w, "ledger:read", p.session)
	// pidl:end resource-managed.session-token.resource
	// pidl:end resource-managed.poll.resource
}

func (l *ledger) serveSession(w http.ResponseWriter, session string, agent *aauth.AgentClaims) {
	// pidl:begin resource-managed.session-request.resource
	// The session token is only good with the key it was issued to; the
	// signature covers AAuth-Access, so it cannot be moved to another
	// request.
	l.mu.Lock()
	jkt, ok := l.sessions[session]
	l.mu.Unlock()
	if !ok || jkt != agent.Cnf.JWK.Thumbprint() {
		aauth.WriteProblem(w, http.StatusUnauthorized, aauth.ErrCodeInvalidRequest, "unknown session")
		return
	}
	respondJSON(w, map[string]any{"entries": []string{"2026-10-01 coffee 4.50"}})
	// pidl:end resource-managed.session-request.resource
}

func TestResourceManaged(t *testing.T) {
	w := newWorld(t)
	led := newLedger(t, w)
	agent := enrollAgent(t, w)
	ctx, hc, resURL := w.ctx, w.hc, led.url

	// sign presents the agent token and signs a request.
	sign := func(req *http.Request) error {
		token, err := agent.MintToken()
		if err != nil {
			return err
		}
		aauth.AttachSignatureKey(req, token)
		return aauth.SignRequest(req, agent.Key, "")
	}

	// pidl:begin resource-managed.request.agent
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resURL+"/api/ledger", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Declare that the agent can bring the person to an interaction URL.
	caps, err := aauth.FormatCapabilities([]string{aauth.CapabilityInteraction})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(aauth.HeaderCapabilities, caps)
	if err := sign(req); err != nil { // agent token in Signature-Key, then sign
		t.Fatal(err)
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end resource-managed.request.agent

	// pidl:begin resource-managed.interaction-required.agent
	// A 202 with requirement=interaction: show the person the URL and
	// code, and poll Location, re-signing each poll, until the resource
	// answers.
	opts := aauth.DeferredOptions{
		Sign:                sign,
		DefaultPollInterval: time.Second,
		OnRequirement: func(r aauth.Requirement) {
			if r.Requirement == aauth.RequirementInteraction {
				openBrowser(w, r.URL+"?code="+url.QueryEscape(r.Code))
			}
		},
	}
	// pidl:end resource-managed.interaction-required.agent

	// pidl:begin resource-managed.poll.agent
	final, err := aauth.FollowDeferred(ctx, hc, req.URL, res, opts)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end resource-managed.poll.agent

	// pidl:begin resource-managed.session-token.agent
	var authorized aauth.AuthorizeResponse
	if err := json.NewDecoder(final.Body).Decode(&authorized); err != nil {
		t.Fatal(err)
	}
	closeBody(t, final)
	// Keep the session token for later calls; a newer AAuth-Access on any
	// response replaces it.
	session := final.Header.Get(aauth.HeaderAAuthAccess)
	if final.StatusCode != http.StatusOK || session == "" {
		t.Fatalf("%s %+v without a session token", final.Status, authorized)
	}
	// pidl:end resource-managed.session-token.agent

	// pidl:begin resource-managed.session-request.agent
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, resURL+"/api/ledger", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(aauth.HeaderAAuthAccess, session) // covered by the signature
	if err := sign(req); err != nil {
		t.Fatal(err)
	}
	res, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// pidl:end resource-managed.session-request.agent

	if got := readOK(t, res); !strings.Contains(got, "coffee") {
		t.Fatalf("ledger %s", got)
	}
}

// openBrowser plays the person, signed in at the resource, opening the
// interaction link.
func openBrowser(w *world, link string) {
	go func() {
		req, err := http.NewRequestWithContext(context.WithoutCancel(w.ctx), http.MethodGet, link, nil)
		if err != nil {
			w.t.Error(err)
			return
		}
		req.AddCookie(&http.Cookie{Name: "session", Value: "alice-session"})
		res, err := w.hc.Do(req)
		if err != nil {
			w.t.Error(err)
			return
		}
		if res.StatusCode != http.StatusOK {
			w.t.Errorf("interaction page: %s", res.Status)
		}
		if err := res.Body.Close(); err != nil {
			w.t.Error(err)
		}
	}()
}

// randomToken returns an unguessable identifier.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
