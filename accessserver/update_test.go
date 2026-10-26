package accessserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// deferred opens a deferred token request at the AS and returns its
// pending URL and id.
func (f *fourParty) deferred(t *testing.T) (loc, id, pt string) {
	t.Helper()
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	pt, rt := f.tokens()
	agentTok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", res.StatusCode)
	}
	loc = res.Header.Get(aauth.HeaderLocation)
	return loc, strings.TrimPrefix(loc, "/as/pending/"), pt
}

// An updated_request replaces what the approver sees, what revocation
// looks up, and the revision Approve must name.
func TestUpdatedRequestRefreshesPending(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	loc, id, pt := f.deferred(t)
	if err := f.as.Ask(ctx, id, Question{Text: "Which folder?"}); err != nil {
		t.Fatal(err)
	}
	pc, err := aauth.VerifyPersonToken(ctx, pt, f.resURL, aauth.TokenVerifyOptions{Resolver: aauth.StaticResolver{f.psURL: f.ps.JWKS()}, InsecureSkipIdentifierCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	wide, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: f.resURL, Audience: f.asURL, Scope: "files:read files:write"}, pc, f.resKey.Key, f.resKey.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	res := f.asRequest(http.MethodPost, loc, `{"action":"updated_request","resource_token":"`+wide+`","presented_token":"`+pt+`"}`)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("update: %d", res.StatusCode)
	}
	p, err := f.as.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if p.Scope != "files:read files:write" || p.ResourceTokenJTI != resourceClaims(t, wide).ID || p.Revision != 1 || p.Deciding {
		t.Fatalf("pending after update %+v", p)
	}
	if err := f.as.Approve(ctx, id, 0, ""); !errors.Is(err, ErrRequestChanged) {
		t.Fatalf("approve of the original: %v", err)
	}
	if err := f.as.Approve(ctx, id, p.Revision, ""); err != nil {
		t.Fatal(err)
	}
	p, err = f.as.PendingRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var tr aauth.AuthTokenResponse
	if err := json.Unmarshal(p.Result.Body, &tr); err != nil {
		t.Fatal(err)
	}
	if got := claims(t, tr.AuthToken).Scope; got != "files:read files:write" {
		t.Fatalf("scope %q", got)
	}
}

// hookStore runs fn once when an auth token is recorded: while Approve
// issues.
type hookStore struct {
	*MemoryStore
	once sync.Once
	fn   func()
}

func (h *hookStore) RecordAuthToken(ctx context.Context, r AuthTokenRecord) error {
	h.once.Do(h.fn)
	return h.MemoryStore.RecordAuthToken(ctx, r)
}

// Approve claims the request: a concurrent Approve, Deny, Ask, or cancel
// finds it taken, and one token is issued.
func TestApproveClaimsRequest(t *testing.T) {
	hs := &hookStore{}
	f := newFourParty(t, false, nil, func(c *Config) {
		hs.MemoryStore = c.Store.(*MemoryStore)
		c.Store = hs
	})
	ctx := context.Background()
	loc, id, pt := f.deferred(t)
	var errs []error
	var cancel int
	hs.fn = func() {
		errs = append(errs, f.as.Approve(ctx, id, 0, ""), f.as.Deny(ctx, id, "no"), f.as.Ask(ctx, id, Question{Text: "?"}))
		res := f.asRequest(http.MethodDelete, loc, "")
		cancel = res.StatusCode
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}
	if err := f.as.Approve(ctx, id, 0, ""); err != nil {
		t.Fatal(err)
	}
	for i, err := range errs {
		if !errors.Is(err, ErrResolved) {
			t.Errorf("concurrent call %d: %v", i, err)
		}
	}
	if cancel != http.StatusGone {
		t.Errorf("cancel: %d", cancel)
	}
	pc, err := aauth.VerifyPersonToken(ctx, pt, f.resURL, aauth.TokenVerifyOptions{Resolver: aauth.StaticResolver{f.psURL: f.ps.JWKS()}, InsecureSkipIdentifierCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := hs.AuthTokensIssuedAgainst(ctx, pc.Issuer, pc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("%d tokens issued", len(recs))
	}
}

// While the Authorizer re-evaluates an answer, a second answer is refused
// rather than authorized (and issued) again.
func TestConcurrentAnswerRefused(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	pt, rt := f.tokens()
	agentTok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	var loc string
	second := 0
	f.setAuthz(func(r *AuthorizationRequest) Decision {
		if r.Claims == nil {
			return RequireClaims("email")
		}
		if second == 0 {
			res := f.asRequest(http.MethodPost, loc, `{"email":"a@example.com"}`)
			second = res.StatusCode
			if err := res.Body.Close(); err != nil {
				t.Error(err)
			}
		}
		return Allow("")
	})
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	loc = res.Header.Get(aauth.HeaderLocation)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	res = f.asRequest(http.MethodPost, loc, `{"email":"a@example.com"}`)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNoContent || second != http.StatusBadRequest {
		t.Fatalf("first answer %d, concurrent answer %d", res.StatusCode, second)
	}
}
