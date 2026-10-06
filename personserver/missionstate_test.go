package personserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// seedMission stores an approved mission for owner, as the mission
// endpoint would.
func (w *world) seedMission(owner AgentRef, expires time.Time) *MissionRecord {
	w.t.Helper()
	blob := []byte(`{"agent":"` + owner.Subject + `","approved_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","description":"test"}`)
	m := &MissionRecord{S256: aauth.MissionS256(blob), Blob: blob, Owner: owner, Person: "alice",
		Status: MissionActive, ApprovedAt: time.Now(), ExpiresAt: expires, Capabilities: []string{"interaction"}}
	if err := w.store.CreateMission(context.Background(), m); err != nil {
		w.t.Fatal(err)
	}
	return m
}

func TestPersonTokenUnderMission(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.personToken(w.agent, w.resURL, "") // bind
	expires := time.Now().Add(20 * time.Minute).Truncate(time.Second)
	m := w.seedMission(agentRefOf(w.agent), expires)
	var seen *TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = r
		return Allow(Grant{})
	})
	tok := w.personToken(w.agent, w.resURL, m.S256)
	pc, err := aauth.VerifyPersonToken(ctx, tok, w.resURL, w.psOpts())
	if err != nil {
		t.Fatal(err)
	}
	if pc.MissionS256 != m.S256 || pc.ExpiresAt.After(expires) {
		t.Fatalf("mission %q exp %v (mission expires %v)", pc.MissionS256, pc.ExpiresAt, expires)
	}
	// Within a mission, omitted capabilities come from its approval.
	if seen.Mission == nil || seen.Mission.S256 != m.S256 || !hasCapability(seen.Capabilities, "interaction") {
		t.Fatalf("decider saw %+v", seen)
	}
	log, err := w.store.MissionLog(ctx, m.S256)
	if err != nil || len(log) != 1 || log[0].Kind != LogTokenRequest {
		t.Fatalf("log %+v %v", log, err)
	}

	// The full three-party flow under the mission carries mission_s256
	// into the resource token and the auth token.
	tr := w.transport(w.agent, w.psClient(w.agent))
	tr.MissionS256 = m.S256
	get(t, tr, w.resURL+"/m")
	_, auths, _ := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	if len(auths) != 1 || auths[0].MissionS256 != m.S256 {
		t.Fatalf("auth records %+v", auths)
	}

	// Terminated: the agent learns why (§8.8).
	pt := w.personToken(w.agent, w.resURL, m.S256)
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	if err := w.store.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
		t.Fatal(err)
	}
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: m.S256})
	_, err = w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: m.S256})
	if res.StatusCode != http.StatusForbidden || tokenCode(err) != aauth.MissionErrTerminated {
		t.Fatalf("terminated: %d %v", res.StatusCode, err)
	}
	_ = res.Body.Close()
	res = w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), `"termination_reason":"revoked"`) {
		t.Fatalf("auth token under a terminated mission: %d %s", res.StatusCode, body)
	}
}

func TestMissionExpiresAndOracle(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.personToken(w.agent, w.resURL, "")
	m := w.seedMission(agentRefOf(w.agent), time.Now().Add(time.Minute))
	// Past expires_at the PS treats the mission as terminated (§8.2).
	w.advance(2 * time.Minute)
	_, err := w.ps.ownedMission(ctx, m.S256, agentRefOf(w.agent))
	var mse *aauth.MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != aauth.TerminationExpired {
		t.Fatalf("expired: %v", err)
	}
	if got, _ := w.store.Mission(ctx, m.S256); got.Status != MissionTerminated {
		t.Fatal("not terminated in the store")
	}
	// Another agent's mission and a missing one look the same (§8.7).
	m2 := w.seedMission(AgentRef{Issuer: "https://x.example", Subject: "aauth:x@x.example"}, time.Time{})
	_, e1 := w.ps.ownedMission(ctx, m2.S256, agentRefOf(w.agent))
	_, e2 := w.ps.ownedMission(ctx, aauth.MissionS256([]byte("nothing")), agentRefOf(w.agent))
	_, e3 := w.ps.ownedMission(ctx, "malformed", agentRefOf(w.agent))
	if e1 != errMissionNotFound || e2 != errMissionNotFound || e3 != errMissionNotFound {
		t.Fatalf("oracle: %v / %v / %v", e1, e2, e3)
	}
	// A token naming a mission the PS has no record of is refused.
	if err := w.ps.checkMission(ctx, aauth.MissionS256([]byte("gone"))); !errors.As(err, &mse) {
		t.Fatalf("missing mission: %v", err)
	}
}
