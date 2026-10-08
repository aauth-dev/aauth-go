package personserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	a := AgentRef{Issuer: "https://ap.example", Subject: "aauth:a@ap.example"}
	b := AgentRef{Issuer: "https://ap.example", Subject: "aauth:b@ap.example"}

	// Bindings: one person per agent.
	if _, err := m.BoundPerson(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := m.Bind(ctx, a, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(ctx, a, "alice"); err != nil {
		t.Fatal("rebinding the same person:", err)
	}
	if err := m.Bind(ctx, a, "bob"); !errors.Is(err, ErrBindingConflict) {
		t.Fatal("rebinding another person:", err)
	}
	if err := m.Unbind(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(ctx, a, "bob"); err != nil {
		t.Fatal("after unbinding:", err)
	}

	// Subjects.
	if err := m.RecordSubject(ctx, "https://r.example", "s1", "bob"); err != nil {
		t.Fatal(err)
	}
	if p, err := m.SubjectPerson(ctx, "https://r.example", "s1"); err != nil || p != "bob" {
		t.Fatal(p, err)
	}
	if _, err := m.SubjectPerson(ctx, "https://r.example", "s2"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Token records and the cascade queries.
	exp := time.Now().Add(time.Hour)
	if err := m.RecordAgentToken(ctx, AgentTokenRecord{Issuer: a.Issuer, JTI: "at1", Subject: a.Subject, Exp: exp}); err != nil {
		t.Fatal(err)
	}
	if r, err := m.AgentToken(ctx, a.Issuer, "at1"); err != nil || r.Subject != a.Subject {
		t.Fatal(r, err)
	}
	if _, err := m.AgentToken(ctx, a.Issuer, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, r := range []PersonTokenRecord{
		{JTI: "p1", Resource: "https://r.example", Subject: "s1", Agent: a, Person: "bob", Exp: exp},
		{JTI: "p2", Resource: "https://r2.example", Subject: "s9", Agent: b, Subagent: a, Person: "bob", Exp: exp,
			UpstreamIssuer: "https://ps.example", UpstreamJTI: "p1"},
	} {
		if err := m.RecordPersonToken(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.MarkPresented(ctx, "p1", "https://as.example"); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkPresented(ctx, "p1", "https://as.example"); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkPresented(ctx, "nope", "https://as.example"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if r, err := m.PersonToken(ctx, "p1"); err != nil || len(r.PresentedTo) != 1 {
		t.Fatal(r, err)
	}
	if _, err := m.PersonToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if rs, err := m.PersonTokensForSubject(ctx, "https://r.example", "s1"); err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	if rs, err := m.PersonTokensFromUpstream(ctx, "https://ps.example", "p1"); err != nil || len(rs) != 1 || rs[0].JTI != "p2" {
		t.Fatal(rs, err)
	}
	for _, r := range []AuthTokenRecord{
		{Issuer: "https://ps.example", JTI: "a1", PersonJTI: "p1", Agent: a, MissionS256: "m1"},
		{Issuer: "https://as.example", JTI: "a2", PersonJTI: "p2", Agent: b, Subagent: a},
	} {
		if err := m.RecordAuthToken(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if r, err := m.AuthToken(ctx, "https://as.example", "a2"); err != nil || r.PersonJTI != "p2" {
		t.Fatal(r, err)
	}
	if _, err := m.AuthToken(ctx, "https://ps.example", "a2"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	ps, as, err := m.TokensForAgent(ctx, a)
	if err != nil || len(ps) != 2 || len(as) != 2 {
		t.Fatal(ps, as, err)
	}
	if rs, err := m.AuthTokensForPersonToken(ctx, "p1"); err != nil || len(rs) != 1 || rs[0].JTI != "a1" {
		t.Fatal(rs, err)
	}
	if rs, err := m.AuthTokensForMission(ctx, "m1"); err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	if ok, _ := m.IsRevoked(ctx, a.Issuer, "at1"); ok {
		t.Fatal("revoked before revocation")
	}
	if err := m.Revoke(ctx, a.Issuer, "at1", exp); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.IsRevoked(ctx, a.Issuer, "at1"); !ok {
		t.Fatal("not revoked")
	}

	// Missions: terminated stays terminated with its first reason.
	mr := &MissionRecord{S256: "m1", Blob: []byte(`{}`), Owner: a, Status: MissionActive}
	if err := m.CreateMission(ctx, mr); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateMission(ctx, mr); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if err := m.AppendMissionLog(ctx, "m1", MissionLogEntry{Kind: LogAudit}); err != nil {
		t.Fatal(err)
	}
	if err := m.AppendMissionLog(ctx, "m2", MissionLogEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := m.TerminateMission(ctx, "m1", "completed"); err != nil {
		t.Fatal(err)
	}
	if err := m.TerminateMission(ctx, "m1", "revoked"); err != nil {
		t.Fatal(err)
	}
	if err := m.TerminateMission(ctx, "m2", "revoked"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if got, err := m.Mission(ctx, "m1"); err != nil || got.Status != MissionTerminated || got.TerminationReason != "completed" {
		t.Fatal(got, err)
	}
	if log, err := m.MissionLog(ctx, "m1"); err != nil || len(log) != 1 {
		t.Fatal(log, err)
	}
	if _, err := m.MissionLog(ctx, "m2"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Pending: optimistic updates and lookups.
	p := &Pending{ID: "x", Kind: KindAuthToken, State: StatePending, CodeCanonical: "ABCD-EFGH",
		ResourceTokenIssuer: "https://r.example", ResourceTokenJTI: "rt1"}
	if err := m.CreatePending(ctx, p); err != nil || p.Version != 1 {
		t.Fatal(p.Version, err)
	}
	if err := m.CreatePending(ctx, p); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	stale, _ := m.Pending(ctx, "x")
	fresh, _ := m.PendingByCode(ctx, "ABCD-EFGH")
	fresh.State = StateInteracting
	if err := m.UpdatePending(ctx, fresh); err != nil || fresh.Version != 2 {
		t.Fatal(err)
	}
	if err := m.UpdatePending(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := m.UpdatePending(ctx, &Pending{ID: "y"}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := m.PendingByCode(ctx, "ZZZZ-ZZZZ"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if ps, err := m.PendingForResourceToken(ctx, "https://r.example", "rt1"); err != nil || len(ps) != 1 {
		t.Fatal(ps, err)
	}
}
