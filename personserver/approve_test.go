package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// deferAuthToken opens a deferred auth token request for scope and
// returns its pending URL and id.
func deferAuthToken(t *testing.T, w *world, pt, scope string) (loc, id string) {
	t.Helper()
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: scope})
	res := w.signed(w.agent, "", http.MethodPost, w.ps.paths.AuthToken, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", res.StatusCode)
	}
	loc = res.Header.Get(aauth.HeaderLocation)
	return loc, strings.TrimPrefix(loc, w.ps.paths.Pending)
}

// pollToken polls loc once and returns the auth token's claims.
func pollToken(t *testing.T, w *world, loc string) *aauth.AuthClaims {
	t.Helper()
	res := w.signed(w.agent, "", http.MethodGet, loc, nil)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var tr aauth.AuthTokenResponse
	if err := json.Unmarshal(b, &tr); err != nil || tr.AuthToken == "" {
		t.Fatalf("poll: %d %s", res.StatusCode, b)
	}
	var ac aauth.AuthClaims
	if err := parseUnverified(tr.AuthToken, &ac); err != nil {
		t.Fatal(err)
	}
	return &ac
}

// An approval binds the revision the person was shown: after the agent
// replaced the request, approving the original fails and grants nothing.
func TestApproveBindsRevision(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	loc, id := deferAuthToken(t, w, pt, "files:read")
	shown, err := w.ps.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ps.Ask(ctx, id, Question{Text: "Which folder?"}); err != nil {
		t.Fatal(err)
	}
	wide := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read files:write"})
	res := w.signed(w.agent, "", http.MethodPost, loc, aauth.ClarificationPost{Action: aauth.ActionUpdatedRequest, ResourceToken: wide, PresentedToken: pt})
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("update: %d", res.StatusCode)
	}
	if err := w.ps.Approve(ctx, id, Grant{Revision: shown.Revision}); !errors.Is(err, ErrRequestChanged) {
		t.Fatalf("approve of the stale revision: %v", err)
	}
	cur, err := w.ps.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !cur.Open() || cur.Revision != 1 || cur.Scope != "files:read files:write" || cur.Approving {
		t.Fatalf("pending %+v", cur)
	}
	if err := w.ps.Approve(ctx, id, Grant{Revision: cur.Revision}); err != nil {
		t.Fatal(err)
	}
	if ac := pollToken(t, w, loc); ac.Scope != "files:read files:write" {
		t.Fatalf("scope %q", ac.Scope)
	}
}

// hookStore runs fn once when an auth token is recorded: in the middle of
// an approval's completion.
type hookStore struct {
	*MemoryStore
	once sync.Once
	fn   func()
}

func (h *hookStore) RecordAuthToken(ctx context.Context, r AuthTokenRecord) error {
	h.once.Do(h.fn)
	return h.MemoryStore.RecordAuthToken(ctx, r)
}

// An approval claims the request before completing it: a second Approve,
// a Deny, a Fail, or the agent's cancel arriving meanwhile finds it taken,
// and exactly one token is issued and delivered.
func TestApproveClaimsRequest(t *testing.T) {
	hs := &hookStore{}
	w := newWorld(t, func(c *Config) {
		hs.MemoryStore = c.Store.(*MemoryStore)
		c.Store = hs
	})
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	loc, id := deferAuthToken(t, w, pt, "files:read")
	var errs []error
	var cancel int
	hs.fn = func() {
		errs = append(errs, w.ps.Approve(ctx, id, Grant{}), w.ps.Deny(ctx, id, "no"), w.ps.Fail(ctx, id, aauth.PollErrAbandoned, ""),
			w.ps.Ask(ctx, id, Question{Text: "?"}))
		res := w.signed(w.agent, "", http.MethodDelete, loc, nil)
		cancel = res.StatusCode
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}
	if err := w.ps.Approve(ctx, id, Grant{}); err != nil {
		t.Fatal(err)
	}
	for i, err := range errs {
		if !errors.Is(err, ErrResolved) {
			t.Errorf("concurrent call %d: %v, want ErrResolved", i, err)
		}
	}
	if cancel != http.StatusGone {
		t.Errorf("cancel during approval: %d", cancel)
	}
	pollToken(t, w, loc)
	_, auths, err := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) != 1 {
		t.Fatalf("%d auth tokens recorded", len(auths))
	}
}
