package e2e_test

import (
	"context"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// runScenario drives the protocol through one deployment, as named steps.
// The steps share state (the agent's tokens, the mission), so each runs only
// if the ones before it passed; `go test -v` shows which step failed.
//
//  1. Three-party at resource A.
//  2. A mission.
//  3. Resource B under the mission (through the access server).
//  4. Audit, update, and completion of the mission.
//  5. Revocation of the agent token, cascading to both resources.
func runScenario(t *testing.T, d *deployment) {
	ctx := context.Background()
	var mission string
	failed := false
	step := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			if failed {
				t.Skip("an earlier step failed")
			}
			fn(t)
			if t.Failed() {
				failed = true
			}
		})
	}

	step("three-party access at A", func(t *testing.T) {
		// The person token waits for Alice's approval, which binds the agent
		// to her; the PS then issues the auth token.
		body, err := d.get(d.transport(""), d.resA.url+"/files")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "iss="+d.psURL) || !strings.Contains(body, "scope=files:read") || !strings.Contains(body, "dwk="+aauth.WellKnownPerson) {
			t.Fatalf("A: %q", body)
		}
		if person, err := d.psStore.BoundPerson(ctx, d.agentRef()); err != nil || person != "alice" {
			t.Fatalf("binding %q %v", person, err)
		}
	})

	step("propose a mission", func(t *testing.T) {
		m, err := d.psc.ProposeMission(ctx, aauth.MissionProposal{Description: "# Reconcile\n\nReconcile the ledger with the files."})
		if err != nil {
			t.Fatal(err)
		}
		mission = m.S256
	})

	step("B refuses a request outside a mission", func(t *testing.T) {
		if _, err := d.get(d.transport(""), d.resB.url+"/ledger"); err == nil {
			t.Fatal("B served without a mission")
		}
	})

	step("access at B under the mission", func(t *testing.T) {
		// The PS federates to the access server, whose deferred approval the
		// ledger owner resolves; the agent receives the AS's auth token.
		body, err := d.get(d.transport(mission), d.resB.url+"/ledger")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "iss="+d.asURL) || !strings.Contains(body, "dwk="+aauth.WellKnownAccess) || !strings.Contains(body, "mission="+mission) {
			t.Fatalf("B: %q", body)
		}
	})

	step("audit, update, and complete the mission", func(t *testing.T) {
		if err := d.psc.Audit(ctx, aauth.AuditRequest{MissionS256: mission, Action: "Reconcile", Result: map[string]any{"rows": 12}}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.psc.UpdateMission(ctx, mission, "Two rows need a person's review."); err != nil {
			t.Fatal(err)
		}
		if err := d.psc.CompleteMission(ctx, mission, "Reconciled; two rows flagged."); err != nil {
			t.Fatal(err)
		}
		m, err := d.ps.Mission(ctx, mission)
		if err != nil || m.Status != personserver.MissionTerminated || m.TerminationReason != aauth.TerminationCompleted {
			t.Fatalf("mission %+v %v", m, err)
		}
		log, err := d.ps.MissionLog(ctx, mission)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]int{}
		for _, e := range log {
			kinds[e.Kind]++
		}
		for _, k := range []string{personserver.LogApproval, personserver.LogTokenRequest, personserver.LogAudit, personserver.LogUpdate, personserver.LogCompletion} {
			if kinds[k] == 0 {
				t.Errorf("mission log has no %s entry: %v", k, kinds)
			}
		}
	})

	step("revoking the agent token cascades to both resources", func(t *testing.T) {
		// The agent provider revokes the agent token at the PS; the PS
		// revokes what it issued to the agent at A and B, and the person
		// token it presented to the AS, which revokes the AS's own token.
		persons, auths, err := d.psStore.TokensForAgent(ctx, d.agentRef())
		if err != nil || len(persons) < 2 || len(auths) < 2 {
			t.Fatalf("records %d %d %v", len(persons), len(auths), err)
		}
		d.sessions.mu.Lock()
		issued := d.sessions.issued[0].Claims
		d.sessions.mu.Unlock()
		if err := d.ap.RevokeAgentToken(ctx, d.psURL, issued.ID, issued.ExpiresAt.Time); err != nil {
			t.Fatal(err)
		}
		at := func(resource string) *resource {
			if resource == d.resB.url {
				return d.resB
			}
			return d.resA
		}
		for _, p := range persons {
			if !at(p.Resource).isRevoked(d.psURL, p.JTI) {
				t.Errorf("person token for %s not revoked there", p.Resource)
			}
		}
		for _, a := range auths {
			if !at(a.Resource).isRevoked(a.Issuer, a.JTI) {
				t.Errorf("auth token from %s for %s not revoked there", a.Issuer, a.Resource)
			}
		}
	})

	step("the revoked agent obtains nothing new", func(t *testing.T) {
		// A refuses the cached tokens and the PS refuses the agent token.
		if _, err := d.get(d.transport(""), d.resA.url+"/files"); err == nil {
			t.Fatal("revoked agent still served")
		}
	})
}
