package personserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// governance configures every governance endpoint, delegating each
// decision to a swappable function.
type governance struct {
	mu         sync.Mutex
	mission    func(*MissionRequest) Decision
	permission func(*PermissionRequest) Decision
	relay      func(*InteractionRequest) Decision
	audits     []aauth.AuditRequest
}

func (g *governance) hook(c *Config) {
	c.MissionApprover = MissionApproverFunc(func(_ context.Context, r *MissionRequest) (Decision, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.mission(r), nil
	})
	c.PermissionDecider = PermissionDeciderFunc(func(_ context.Context, r *PermissionRequest) (Decision, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.permission(r), nil
	})
	c.InteractionRelay = InteractionRelayFunc(func(_ context.Context, r *InteractionRequest) (Decision, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.relay(r), nil
	})
	c.Audit = true
	c.AuditSink = func(_ context.Context, _ AgentRef, r aauth.AuditRequest) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.audits = append(g.audits, r)
	}
}

func newGovernedWorld(t *testing.T) (*world, *governance) {
	g := &governance{
		mission:    func(*MissionRequest) Decision { return Allow(Grant{}) },
		permission: func(*PermissionRequest) Decision { return Allow(Grant{}) },
		relay:      func(*InteractionRequest) Decision { return Allow(Grant{Answer: "yes"}) },
	}
	w := newWorld(t, g.hook)
	w.personToken(w.agent, w.resURL, "") // bind the agent to alice
	return w, g
}

func (g *governance) set(fn func(*governance)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn(g)
}

func TestGovernanceMetadata(t *testing.T) {
	w, _ := newGovernedWorld(t)
	md := w.ps.Metadata()
	for name, v := range map[string]string{
		"mission": md.MissionEndpoint, "permission": md.PermissionEndpoint, "audit": md.AuditEndpoint,
		"interaction": md.InteractionEndpoint, "revocation": md.RevocationEndpoint,
	} {
		if !strings.HasPrefix(v, w.psURL+"/ps/") {
			t.Errorf("%s endpoint %q", name, v)
		}
	}
	// Without the interfaces the optional endpoints are not published.
	plain := newWorld(t, nil).ps.Metadata()
	if plain.MissionEndpoint != "" || plain.PermissionEndpoint != "" || plain.AuditEndpoint != "" || plain.InteractionEndpoint != "" {
		t.Fatalf("optional endpoints published: %+v", plain)
	}
}

func TestMissionLifecycle(t *testing.T) {
	w, g := newGovernedWorld(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	var proposed *MissionRequest
	g.set(func(g *governance) {
		g.mission = func(r *MissionRequest) Decision {
			if r.Kind != KindMissionProposal {
				return Allow(Grant{})
			}
			proposed = r
			return Allow(Grant{Mission: &MissionGrant{
				Description:  "# Trip\n\nBook flights only.",
				Tools:        []aauth.MissionTool{{Name: "Search"}},
				Resources:    []string{"https://flights.example"},
				ExpiresAt:    expires,
				Capabilities: []string{"interaction"},
				Extra:        map[string]any{"budget": 5000},
			}})
		}
	})
	c := w.psClient(w.agent)
	am, err := c.ProposeMission(ctx, aauth.MissionProposal{
		Description: "# Trip\n\nPlan and book a trip.",
		Tools:       []aauth.MissionTool{{Name: "Search"}, {Name: "Book"}},
		Resources:   []string{"https://flights.example", "https://hotels.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proposed.Person != "alice" || len(proposed.Proposal.Tools) != 2 {
		t.Fatalf("approver saw %+v", proposed)
	}
	if am.Mission.Description != "# Trip\n\nBook flights only." || len(am.Mission.ApprovedTools) != 1 ||
		len(am.Mission.ApprovedResources) != 1 || am.Mission.ExpiresAt == "" || !bytes.Contains(am.Blob, []byte(`"budget":5000`)) {
		t.Fatalf("mission %+v / %s", am.Mission, am.Blob)
	}
	// The PS stored exactly the bytes s256 covers and serves them back.
	rec, err := w.ps.Mission(ctx, am.S256)
	if err != nil || !bytes.Equal(rec.Blob, am.Blob) || aauth.MissionS256(rec.Blob) != am.S256 || !rec.ExpiresAt.Equal(expires) {
		t.Fatalf("record %+v %v", rec, err)
	}
	pt := am.PersonTokens["https://flights.example"]
	pc, err := aauth.VerifyPersonToken(ctx, pt, "https://flights.example", w.psOpts())
	if err != nil || pc.MissionS256 != am.S256 || pc.ExpiresAt.After(expires) {
		t.Fatalf("approval person token %+v %v", pc, err)
	}
	if len(am.Capabilities) != 1 || am.Capabilities[0] != "interaction" {
		t.Fatalf("capabilities %v", am.Capabilities)
	}

	// An update is accepted into the log with the s256 of its bytes.
	ur, err := c.UpdateMission(ctx, am.S256, "Hotel unavailable; booking another.")
	if err != nil {
		t.Fatal(err)
	}
	log, err := w.ps.MissionLog(ctx, am.S256)
	if err != nil {
		t.Fatal(err)
	}
	last := log[len(log)-1]
	if last.Kind != LogUpdate || last.S256 != ur.S256 || aauth.MissionS256(last.Body) != ur.S256 {
		t.Fatalf("update log %+v, response %+v", last, ur)
	}

	// Completion: the person asks a follow-up, then accepts.
	g.set(func(g *governance) {
		g.mission = func(r *MissionRequest) Decision {
			if r.Kind == KindMissionCompletion {
				return DeferApproval()
			}
			return Allow(Grant{})
		}
	})
	w.setNotify(func(p *Pending) {
		if !p.Open() || p.Kind != KindMissionCompletion || p.Question != nil {
			return
		}
		go func() {
			var err error
			if len(p.Transcript) == 0 {
				err = w.ps.Ask(ctx, p.ID, Question{Text: "Was the itinerary sent?"})
			} else {
				err = w.ps.Approve(ctx, p.ID, Grant{})
			}
			if err != nil {
				t.Error(err)
			}
		}()
	})
	c.OnClarification = func(aauth.Clarification) (aauth.ClarificationReply, error) {
		return aauth.ClarificationReply{Text: "Yes, by email."}, nil
	}
	if err := c.CompleteMission(ctx, am.S256, "Booked flights."); err != nil {
		t.Fatal(err)
	}
	rec, _ = w.ps.Mission(ctx, am.S256)
	if rec.Status != MissionTerminated || rec.TerminationReason != aauth.TerminationCompleted {
		t.Fatalf("after completion %+v", rec)
	}
	// A terminated mission is distinguishable to its owner.
	_, err = c.UpdateMission(ctx, am.S256, "more")
	var mse *aauth.MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != aauth.TerminationCompleted {
		t.Fatalf("update after completion: %v", err)
	}
}

func TestMissionProposalDeferredAndErrors(t *testing.T) {
	w, g := newGovernedWorld(t)
	ctx := context.Background()
	g.set(func(g *governance) { g.mission = func(*MissionRequest) Decision { return DeferApproval() } })
	w.setNotify(func(p *Pending) {
		if p.Open() && p.Kind == KindMissionProposal {
			go func() {
				if err := w.ps.Approve(ctx, p.ID, Grant{}); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	am, err := w.psClient(w.agent).ProposeMission(ctx, aauth.MissionProposal{Description: "Do the thing"})
	if err != nil || am.Mission.Description != "Do the thing" {
		t.Fatalf("%+v %v", am, err)
	}
	w.setNotify(nil)
	// Proposal errors.
	for name, body := range map[string]any{
		"no description": aauth.MissionProposal{},
		"bad resource":   aauth.MissionProposal{Description: "x", Resources: []string{""}},
	} {
		res := w.signed(w.agent, "", http.MethodPost, "/ps/mission", body)
		if got := errorCode(t, res); got != aauth.TokenErrInvalidRequest {
			t.Errorf("%s: %q", name, got)
		}
	}
	g.set(func(g *governance) {
		g.mission = func(*MissionRequest) Decision {
			return Allow(Grant{Mission: &MissionGrant{Resources: []string{"https://never-proposed.example"}}})
		}
	})
	res := w.signed(w.agent, "", http.MethodPost, "/ps/mission", aauth.MissionProposal{Description: "x"})
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("unproposed resource approved: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	g.set(func(g *governance) { g.mission = func(*MissionRequest) Decision { return Deny("no") } })
	_, err = w.psClient(w.agent).ProposeMission(ctx, aauth.MissionProposal{Description: "x"})
	if err == nil {
		t.Fatal("denied proposal succeeded")
	}

	// Mission URL errors: malformed s256, bad action, and the same answer
	// for a missing mission and another agent's mission (§8.7).
	res = w.signed(w.agent, "", http.MethodPost, "/ps/mission/short", aauth.MissionAction{Action: "update", Description: "x"})
	if got := errorCode(t, res); res.StatusCode != http.StatusBadRequest || got != aauth.ErrCodeInvalidRequest {
		t.Fatalf("malformed s256: %d %q", res.StatusCode, got)
	}
	path := "/ps/mission/" + am.S256
	for _, body := range []any{aauth.MissionAction{Action: "finish"}, aauth.MissionAction{Action: "update"}, "x"} {
		res = w.signed(w.agent, "", http.MethodPost, path, body)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("bad action %v: %d", body, res.StatusCode)
		}
		_ = res.Body.Close()
	}
	other := w.otherAgent("other")
	notOwner := w.signed(other, "", http.MethodPost, path, aauth.MissionAction{Action: "update", Description: "x"})
	missing := w.signed(other, "", http.MethodPost, "/ps/mission/"+aauth.MissionS256([]byte("none")), aauth.MissionAction{Action: "update", Description: "x"})
	b1, _ := io.ReadAll(notOwner.Body)
	b2, _ := io.ReadAll(missing.Body)
	_ = notOwner.Body.Close()
	_ = missing.Body.Close()
	if notOwner.StatusCode != http.StatusNotFound || missing.StatusCode != notOwner.StatusCode || !bytes.Equal(b1, b2) ||
		notOwner.Header.Get("Content-Type") != missing.Header.Get("Content-Type") {
		t.Fatalf("oracle: %d %s / %d %s", notOwner.StatusCode, b1, missing.StatusCode, b2)
	}
}

func TestPermission(t *testing.T) {
	w, g := newGovernedWorld(t)
	ctx := context.Background()
	c := w.psClient(w.agent)
	pr, err := c.RequestPermission(ctx, aauth.PermissionRequest{Action: "SendEmail"})
	if err != nil || !pr.Granted() {
		t.Fatalf("%+v %v", pr, err)
	}
	g.set(func(g *governance) { g.permission = func(*PermissionRequest) Decision { return Deny("not to them") } })
	pr, err = c.RequestPermission(ctx, aauth.PermissionRequest{Action: "SendEmail"})
	if err != nil || pr.Granted() || pr.Reason != "not to them" {
		t.Fatalf("denied: %+v %v", pr, err)
	}
	// Deferred to the person, under a mission; logged there.
	m := w.seedMission(agentRefOf(w.agent), time.Time{})
	var seen *PermissionRequest
	g.set(func(g *governance) {
		g.permission = func(r *PermissionRequest) Decision {
			seen = r
			return DeferApproval()
		}
	})
	for i, resolve := range []func(id string) error{
		func(id string) error { return w.ps.Approve(ctx, id, Grant{}) },
		func(id string) error { return w.ps.Deny(ctx, id, "no") },
	} {
		w.setNotify(func(p *Pending) {
			if p.Open() && p.Kind == KindPermission {
				go func() {
					if err := resolve(p.ID); err != nil {
						t.Error(err)
					}
				}()
			}
		})
		pr, err = c.RequestPermission(ctx, aauth.PermissionRequest{Action: "Write", MissionS256: m.S256})
		if err != nil || pr.Granted() != (i == 0) {
			t.Fatalf("deferred %d: %+v %v", i, pr, err)
		}
	}
	if seen.Mission == nil || seen.Person != "alice" || seen.Request.Action != "Write" {
		t.Fatalf("decider saw %+v", seen)
	}
	log, _ := w.ps.MissionLog(ctx, m.S256)
	if len(log) < 2 || log[0].Kind != LogPermission {
		t.Fatalf("log %+v", log)
	}
	// Errors: no action; a terminated mission.
	res := w.signed(w.agent, "", http.MethodPost, "/ps/permission", aauth.PermissionRequest{})
	if got := errorCode(t, res); got != aauth.TokenErrInvalidRequest {
		t.Fatalf("no action: %q", got)
	}
	if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
		t.Fatal(err)
	}
	_, err = c.RequestPermission(ctx, aauth.PermissionRequest{Action: "Write", MissionS256: m.S256})
	var mse *aauth.MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != aauth.TerminationRevoked {
		t.Fatalf("terminated: %v", err)
	}
}

func TestAudit(t *testing.T) {
	w, g := newGovernedWorld(t)
	ctx := context.Background()
	c := w.psClient(w.agent)
	m := w.seedMission(agentRefOf(w.agent), time.Time{})
	if err := c.Audit(ctx, aauth.AuditRequest{MissionS256: m.S256, Action: "WebSearch", Result: map[string]any{"n": 12}}); err != nil {
		t.Fatal(err)
	}
	log, _ := w.ps.MissionLog(ctx, m.S256)
	if len(log) != 1 || log[0].Kind != LogAudit || !bytes.Contains(log[0].Body, []byte("WebSearch")) || len(g.audits) != 1 {
		t.Fatalf("log %+v sink %+v", log, g.audits)
	}
	for name, c := range map[string]struct {
		body   any
		status int
	}{
		"no mission":    {aauth.AuditRequest{Action: "x"}, http.StatusBadRequest},
		"no action":     {aauth.AuditRequest{MissionS256: m.S256}, http.StatusBadRequest},
		"bad body":      {"x", http.StatusBadRequest},
		"not a mission": {aauth.AuditRequest{MissionS256: aauth.MissionS256([]byte("x")), Action: "x"}, http.StatusNotFound},
	} {
		res := w.signed(w.agent, "", http.MethodPost, "/ps/audit", c.body)
		if res.StatusCode != c.status {
			t.Errorf("%s: %d", name, res.StatusCode)
		}
		_ = res.Body.Close()
	}
	if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationAdministrative); err != nil {
		t.Fatal(err)
	}
	var mse *aauth.MissionStatusError
	if err := c.Audit(ctx, aauth.AuditRequest{MissionS256: m.S256, Action: "x"}); !errors.As(err, &mse) {
		t.Fatalf("terminated: %v", err)
	}
}

func TestInteractionEndpoint(t *testing.T) {
	w, g := newGovernedWorld(t)
	ctx := context.Background()
	c := w.psClient(w.agent)
	ir, err := c.RequestInteraction(ctx, aauth.InteractionRequest{Type: aauth.InteractionTypeQuestion, Question: "Refundable?"})
	if err != nil || ir.Answer != "yes" {
		t.Fatalf("%+v %v", ir, err)
	}
	// A question the person answers later.
	g.set(func(g *governance) { g.relay = func(*InteractionRequest) Decision { return DeferApproval() } })
	w.setNotify(func(p *Pending) {
		if p.Open() && p.Kind == KindInteraction && p.Interaction.Type == aauth.InteractionTypeQuestion {
			go func() {
				if err := w.ps.Approve(ctx, p.ID, Grant{Answer: "the refundable one"}); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	if ir, err = c.RequestInteraction(ctx, aauth.InteractionRequest{Type: aauth.InteractionTypeQuestion, Question: "Which?"}); err != nil || ir.Answer != "the refundable one" {
		t.Fatalf("%+v %v", ir, err)
	}
	// A resource-hosted interaction relayed through the PS: the person
	// engages, then the PS has done all it can (§7.6.2).
	w.setNotify(func(p *Pending) {
		if !p.Open() || p.Kind != KindInteraction {
			return
		}
		go func() {
			var err error
			if p.State == StatePending {
				err = w.ps.MarkInteracting(ctx, p.ID)
			} else {
				err = w.ps.Approve(ctx, p.ID, Grant{})
			}
			if err != nil {
				t.Error(err)
			}
		}()
	})
	req := aauth.Requirement{Requirement: aauth.RequirementInteraction, URL: "https://booking.example/confirm", Code: "X7K2-M9P4"}
	if _, err := c.RelayInteraction(ctx, req, "Confirm the booking", ""); err != nil {
		t.Fatal(err)
	}
	// A relay with max_wait resolves when the window elapses.
	w.setNotify(nil)
	g.set(func(g *governance) { g.relay = func(*InteractionRequest) Decision { return DeferApproval() } })
	done := make(chan error, 1)
	go func() {
		_, err := c.RequestInteraction(ctx, aauth.InteractionRequest{Type: aauth.InteractionTypePayment, URL: "https://pay.example/approve", Code: "X7K2-M9P4", MaxWait: 1})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not resolve after max_wait")
	}
	// No channel: the agent directs the person itself.
	g.set(func(g *governance) { g.relay = func(*InteractionRequest) Decision { return Deny("") } })
	_, err = c.RequestInteraction(ctx, aauth.InteractionRequest{Type: aauth.InteractionTypeInteraction, URL: "https://r.example/i", Code: "X7K2-M9P4"})
	if !errors.Is(err, aauth.ErrInteractionUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
	g.set(func(g *governance) {
		g.relay = func(*InteractionRequest) Decision { return Decision{Code: aauth.TokenErrUserUnreachable} }
	})
	_, err = c.RequestInteraction(ctx, aauth.InteractionRequest{Type: aauth.InteractionTypeQuestion, Question: "?"})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.TokenErrUserUnreachable || pe.Status != http.StatusForbidden {
		t.Fatalf("unreachable: %v", err)
	}
	for _, body := range []aauth.InteractionRequest{
		{Type: "chat"},
		{Type: aauth.InteractionTypeQuestion},
		{Type: aauth.InteractionTypeInteraction, URL: "http://r.example/i"},
		{Type: aauth.InteractionTypePayment, URL: "https://r.example/i?x=1"},
	} {
		res := w.signed(w.agent, "", http.MethodPost, "/ps/interaction", body)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%+v: %d", body, res.StatusCode)
		}
		_ = res.Body.Close()
	}
}

func TestMarshalBlobExtra(t *testing.T) {
	b, err := marshalBlob(missionBlob{Agent: "a", ApprovedAt: "t", Description: "d"}, map[string]any{"x": 1})
	if err != nil || !bytes.Contains(b, []byte(`"x":1`)) {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := marshalBlob(missionBlob{}, map[string]any{"agent": "b"}); err == nil {
		t.Fatal("collision accepted")
	}
	if _, err := marshalBlob(missionBlob{}, map[string]any{"f": func() {}}); err == nil {
		t.Fatal("unmarshalable extra accepted")
	}
}

// A permission or interaction request deferred to the person must not be
// granted after its mission ended while it waited.
func TestDeferredGovernanceAfterMissionEnds(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		body       func(s256 string) any
	}{
		{"permission", "/ps/permission", func(s256 string) any {
			return aauth.PermissionRequest{Action: "SendEmail", MissionS256: s256}
		}},
		{"interaction", "/ps/interaction", func(s256 string) any {
			return aauth.InteractionRequest{Type: aauth.InteractionTypeQuestion, Question: "ok?", MissionS256: s256}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, g := newGovernedWorld(t)
			ctx := context.Background()
			m := w.seedMission(agentRefOf(w.agent), time.Time{})
			g.set(func(g *governance) {
				g.permission = func(*PermissionRequest) Decision { return DeferApproval() }
				g.relay = func(*InteractionRequest) Decision { return DeferApproval() }
			})
			res := w.signed(w.agent, "", http.MethodPost, tc.path, tc.body(m.S256))
			loc := res.Header.Get(aauth.HeaderLocation)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusAccepted || loc == "" {
				t.Fatalf("defer: %d %q", res.StatusCode, loc)
			}
			id := strings.TrimPrefix(loc, "/ps/pending/")
			if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
				t.Fatal(err)
			}
			if err := w.ps.Approve(ctx, id, Grant{Answer: "yes"}); err != nil {
				t.Fatal(err)
			}
			p, err := w.ps.PendingRequest(ctx, id)
			if err != nil || p.Result == nil {
				t.Fatalf("pending %+v %v", p, err)
			}
			if p.Result.Status == http.StatusOK || strings.Contains(string(p.Result.Body), "granted") {
				t.Fatalf("granted after termination: %d %s", p.Result.Status, p.Result.Body)
			}
		})
	}
}
