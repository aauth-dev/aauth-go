package aauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// missionPS is a PS serving the mission endpoint (§8).
type missionPS struct {
	c          *PSClient
	key        *Agent
	blob       []byte // the persisted blob of the approved mission
	tamper     func(*MissionApproval)
	terminated atomic.Bool
	last       atomic.Pointer[MissionAction]
}

func newMissionPS(t *testing.T, agent *Agent) *missionPS {
	t.Helper()
	m := &missionPS{}
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	var err error
	if m.key, err = NewAgent(psID); err != nil {
		t.Fatal(err)
	}
	var base string
	var approval atomic.Pointer[MissionApproval]
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mission", func(rw http.ResponseWriter, r *http.Request) {
		caller, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var p MissionProposal
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Description == "" {
			WriteProblem(rw, http.StatusBadRequest, ErrCodeInvalidRequest, "bad proposal")
			return
		}
		// The persisted bytes: deliberately not Go's canonical encoding,
		// and with a member this library does not model.
		m.blob = []byte(`{"agent": "` + caller.Subject + `", "approved_at": "2026-04-07T14:30:00Z", "expires_at": "2099-05-07T14:30:00Z",
  "description": "# Plan Japan Vacation (approved)", "approved_resources": ["` + strings.Join(p.Resources, `", "`) + `"], "x_cost_center": "travel"}`)
		s256 := MissionS256(m.blob)
		tokens := map[string]string{}
		for _, res := range p.Resources {
			tok, _, err := IssuePersonToken(PersonTokenParams{
				Issuer: base, Resource: res, Subject: "person-1", Agent: caller, MissionS256: s256,
				InsecureSkipIdentifierCheck: true,
			}, m.key.Key, m.key.JWK().Kid)
			if err != nil {
				WriteTokenError(rw, err)
				return
			}
			tokens[res] = tok
		}
		ma := NewMissionApproval(m.blob, []string{"interaction"}, tokens)
		if m.tamper != nil {
			m.tamper(&ma)
		}
		approval.Store(&ma)
		// The person reviews it first.
		WriteApprovalPending(rw, "/pending/m1", 0)
	})
	mux.HandleFunc("GET /pending/m1", func(rw http.ResponseWriter, _ *http.Request) {
		writeJSON(t, rw, approval.Load())
	})
	mux.HandleFunc("POST /mission/{s256}", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		s256 := r.PathValue("s256")
		var a MissionAction
		if !ValidMissionS256(s256) || json.NewDecoder(r.Body).Decode(&a) != nil || a.Validate() != nil {
			WriteProblem(rw, http.StatusBadRequest, ErrCodeInvalidRequest, "")
			return
		}
		if m.blob == nil || s256 != MissionS256(m.blob) {
			WriteProblem(rw, http.StatusNotFound, ErrCodeMissionNotFound, "")
			return
		}
		if m.terminated.Load() {
			WriteMissionTerminated(rw, TerminationCompleted)
			return
		}
		m.last.Store(&a)
		if a.Action == MissionActionUpdate {
			writeJSON(t, rw, MissionUpdateResponse{S256: MissionS256([]byte(a.Description))})
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	m.c = NewPSClient(base, agent)
	return m
}

func TestMissionLifecycle(t *testing.T) {
	agent := testAgent(t)
	ps := newMissionPS(t, agent)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resources := []string{"https://flights.example", "https://hotels.example"}
	am, err := ps.c.ProposeMission(ctx, MissionProposal{
		Description: "# Plan Japan Vacation",
		Tools:       []MissionTool{{Name: "WebSearch", Description: "Search the web"}},
		Resources:   resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	// §8.2.1: s256 covers the exact persisted bytes, returned unchanged.
	if string(am.Blob) != string(ps.blob) || am.S256 != MissionS256(ps.blob) {
		t.Fatalf("blob %q, s256 %s", am.Blob, am.S256)
	}
	if am.Mission.Agent != agent.ID.String() || am.Mission.Description != "# Plan Japan Vacation (approved)" || len(am.Mission.ApprovedResources) != 2 {
		t.Fatalf("mission %+v", am.Mission)
	}
	if exp, err := am.Mission.Expiry(); err != nil || exp.Year() != 2099 {
		t.Fatalf("expiry %v, %v", exp, err)
	}
	if len(am.Capabilities) != 1 || len(am.PersonTokens) != 2 {
		t.Fatalf("approval %+v", am)
	}
	// The approval's person tokens are cached under the mission: no person
	// token endpoint is needed (this PS has none).
	for _, r := range resources {
		tok, err := ps.c.PersonToken(ctx, PersonTokenRequest{Resource: r, MissionS256: am.S256})
		if err != nil || tok != am.PersonTokens[r] {
			t.Fatalf("%s: cached person token %v", r, err)
		}
	}

	// §8.4: an update returns the update's s256; the mission is unchanged.
	ur, err := ps.c.UpdateMission(ctx, am.S256, "# Hotel unavailable")
	if err != nil || ur.S256 != MissionS256([]byte("# Hotel unavailable")) {
		t.Fatalf("update %+v, %v", ur, err)
	}
	// §8.5: completion with a summary.
	if err := ps.c.CompleteMission(ctx, am.S256, "Booked flights and hotel."); err != nil {
		t.Fatal(err)
	}
	if a := ps.last.Load(); a.Action != MissionActionCompletion || a.Summary != "Booked flights and hotel." {
		t.Fatalf("PS saw %+v", a)
	}

	// §8.7 errors.
	ps.terminated.Store(true)
	var mse *MissionStatusError
	if err := ps.c.CompleteMission(ctx, am.S256, "again"); !errors.As(err, &mse) || mse.TerminationReason != TerminationCompleted {
		t.Fatalf("terminated: err = %v", err)
	}
	other := MissionS256([]byte("another mission"))
	var pe *ProblemError
	if _, err := ps.c.UpdateMission(ctx, other, "x"); !errors.As(err, &pe) || pe.Code != ErrCodeMissionNotFound || pe.Status != http.StatusNotFound {
		t.Fatalf("not found: err = %v", err)
	}
	if err := ps.c.CompleteMission(ctx, "not-an-s256", "x"); err == nil {
		t.Fatal("malformed s256 accepted")
	}
	if _, err := ps.c.UpdateMission(ctx, am.S256, ""); err == nil {
		t.Fatal("update without description accepted")
	}
}

func TestProposeMissionVerifiesApproval(t *testing.T) {
	agent := testAgent(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, tamper := range map[string]func(*MissionApproval){
		"s256 of other bytes": func(ma *MissionApproval) { ma.S256 = MissionS256([]byte("{}")) },
		"blob not base64url":  func(ma *MissionApproval) { ma.Mission = "!!" },
		"another agent's mission": func(ma *MissionApproval) {
			blob := []byte(`{"agent":"aauth:someone@else.example","approved_at":"2026-04-07T14:30:00Z","description":"x"}`)
			*ma = NewMissionApproval(blob, nil, nil)
		},
		"blob without approved_at": func(ma *MissionApproval) {
			*ma = NewMissionApproval([]byte(`{"agent":"`+agent.ID.String()+`","description":"x"}`), nil, nil)
		},
		"person token for another resource": func(ma *MissionApproval) {
			ma.PersonTokens["https://other.example"] = ma.PersonTokens["https://flights.example"]
		},
	} {
		ps := newMissionPS(t, agent)
		ps.tamper = tamper
		if _, err := ps.c.ProposeMission(ctx, MissionProposal{Description: "d", Resources: []string{"https://flights.example"}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ps := newMissionPS(t, agent)
	if _, err := ps.c.ProposeMission(ctx, MissionProposal{}); err == nil {
		t.Error("proposal without description accepted")
	}
	if _, err := ps.c.ProposeMission(ctx, MissionProposal{Description: "d", Resources: []string{"http://insecure.example"}}); err == nil {
		t.Error("non-server-identifier resource accepted")
	}
}

func TestMissionS256Helpers(t *testing.T) {
	blob := []byte(`{"agent":"aauth:assistant@agent.example","approved_at":"2026-04-07T14:30:00Z","description":"d"}`)
	s := MissionS256(blob)
	if !ValidMissionS256(s) || VerifyMissionS256(blob, s) != nil {
		t.Fatalf("s256 %q", s)
	}
	if !errors.Is(VerifyMissionS256(append(blob, ' '), s), ErrMissionDigest) {
		t.Fatal("trailing byte not detected")
	}
	for _, bad := range []string{"", "short", s + "A", strings.Repeat("=", 43), base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + "AA"} {
		if ValidMissionS256(bad) {
			t.Errorf("%q valid", bad)
		}
	}
	ma := NewMissionApproval(blob, nil, nil)
	m, got, err := ma.Decode()
	if err != nil || string(got) != string(blob) || m.Agent != "aauth:assistant@agent.example" {
		t.Fatalf("decode %+v %q %v", m, got, err)
	}
	if exp, err := m.Expiry(); err != nil || !exp.IsZero() {
		t.Fatalf("no expires_at: %v %v", exp, err)
	}
	for _, a := range []MissionAction{{}, {Action: "terminate"}, {Action: MissionActionUpdate}, {Action: MissionActionCompletion}} {
		if a.Validate() == nil {
			t.Errorf("%+v valid", a)
		}
	}
	if !errors.Is(MissionAction{Action: "x"}.Validate(), ErrUnknownAction) {
		t.Error("unknown action is not ErrUnknownAction")
	}
}
