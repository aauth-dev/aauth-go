package walkthrough_test

import (
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// decideAuthToken is the person server's decision on an auth token
// request.
func decideAuthToken(r *personserver.TokenRequest) personserver.Decision {
	// pidl:begin consent.interaction-required.ps
	// The PS asks the person before granting access. Deferring with
	// requirement=interaction answers 202 with Location, the
	// interaction URL and a single-use code; the agent polls Location
	// while the person decides at the URL.
	if r.ResourceToken == nil || r.Scope == "" {
		return personserver.Deny("no scope requested")
	}
	return personserver.DeferInteraction()
	// pidl:end consent.interaction-required.ps
}

// approvals counts consent page approvals, for tests.
var approvals atomic.Int64

// consentPage is the person server's interaction page (Config.InteractionURL).
func (w *world) consentPage(rw http.ResponseWriter, r *http.Request) {
	// pidl:begin consent.approve.ps
	p, err := w.ps.ConsumeCodeFor(r.Context(), r.URL.Query().Get("code"), r.RemoteAddr)
	if err != nil {
		http.Error(rw, "this link has expired or was already used", http.StatusBadRequest)
		return
	}
	// The code only links this browser to the request: authenticate the
	// person before acting on their decision.
	person, ok := signedInPerson(r)
	if !ok {
		http.Error(rw, "sign in first", http.StatusUnauthorized)
		return
	}
	// After showing what the agent asks for, record the approval.
	if err := w.ps.Approve(r.Context(), p.ID, personserver.Grant{Person: person}); err != nil {
		http.Error(rw, err.Error(), http.StatusConflict)
		return
	}
	// pidl:end consent.approve.ps
	approvals.Add(1)
	if _, err := fmt.Fprintln(rw, "Approved. You can return to your agent."); err != nil {
		w.t.Error(err)
	}
}

// signedInPerson stands in for the PS's own login session.
func signedInPerson(r *http.Request) (string, bool) {
	c, err := r.Cookie("session")
	if err != nil || c.Value != "alice-session" {
		return "", false
	}
	return "alice", true
}

// newPSClient returns the agent's client for its person server, with the
// consent fragment's agent side: directing the person, and polling.
func newPSClient(t *testing.T, w *world, agent *aauth.Agent) *aauth.PSClient {
	t.Helper()
	psc := aauth.NewPSClient(agent.PS, agent)
	psc.HTTPClient = w.hc

	// pidl:begin consent.direct-user.agent
	// When the PS defers for the person, show them where to go. The
	// client keeps polling while they decide.
	psc.OnRequirement = func(r aauth.Requirement) {
		if r.Requirement != aauth.RequirementInteraction {
			return
		}
		link := r.URL + "?code=" + url.QueryEscape(r.Code)
		showUser(w, link, r.Code) // open a browser, or print the link and code
	}
	// pidl:end consent.direct-user.agent

	// pidl:begin consent.poll.agent
	// The pending URL is polled with GET, re-signed each time. Prefer:
	// wait asks the PS to hold each poll open until something changes,
	// rather than answering at once with another 202.
	psc.PreferWaitSeconds = 10
	// pidl:end consent.poll.agent

	if _, err := psc.Discover(w.ctx); err != nil {
		t.Fatal(err)
	}
	return psc
}

// showUser plays the person: alice, already signed in to her PS, opens
// the link.
func showUser(w *world, link, code string) {
	if code == "" {
		w.t.Error("interaction without a code")
		return
	}
	go func() {
		req, err := http.NewRequestWithContext(w.ctx, http.MethodGet, link, nil)
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
		if err := res.Body.Close(); err != nil {
			w.t.Error(err)
		}
		if res.StatusCode != http.StatusOK {
			w.t.Errorf("consent page: %s", res.Status)
		}
	}()
}

func TestConsent(t *testing.T) {
	w := newWorld(t)
	res := newDocumentsResource(t, w, w.psURL)
	before := approvals.Load()
	agent := enrollAgent(t, w)
	psc := newPSClient(t, w, agent)
	if got := authorizeAndCall(t, w, agent, psc, res); got == "" {
		t.Fatal("no response")
	}
	if approvals.Load() != before+1 {
		t.Fatalf("approvals = %d, want one more than %d", approvals.Load(), before)
	}
}
