package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAudit(t *testing.T) {
	agent := testAgent(t)
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	var got AuditRequest
	var raw map[string]json.RawMessage
	terminated := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit" {
			http.NotFound(rw, r)
			return
		}
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		if terminated {
			WriteMissionTerminated(rw, TerminationExpired)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(b, &got); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		rw.WriteHeader(http.StatusCreated) // §7.8.2
	}))
	defer srv.Close()

	c := NewPSClient(srv.URL, agent)
	err := c.Audit(context.Background(), AuditRequest{
		MissionS256: mission,
		Action:      "SendEmail",
		Description: "sent the itinerary",
		Parameters:  map[string]any{"to": "user@example.com"},
		Result:      map[string]any{"message_id": "m-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != "SendEmail" || got.MissionS256 != mission || got.Parameters["to"] != "user@example.com" {
		t.Fatalf("PS recorded %+v", got)
	}
	// §7.8.1: the mission is named by mission_s256; there is no mission
	// object.
	if _, ok := raw["mission"]; ok || string(raw["mission_s256"]) != `"`+mission+`"` {
		t.Fatalf("wire body %v", raw)
	}

	// Mission required client-side (§7.8: no audit outside a mission).
	if err := c.Audit(context.Background(), AuditRequest{Action: "X"}); err == nil {
		t.Fatal("audit without mission accepted")
	}

	// Terminated mission → typed §8.8 error; agent must stop.
	terminated = true
	err = c.Audit(context.Background(), AuditRequest{MissionS256: mission, Action: "SendEmail"})
	var mse *MissionStatusError
	if !errors.As(err, &mse) || mse.MissionStatus != MissionStatusTerminated || mse.Code != MissionErrTerminated || mse.TerminationReason != TerminationExpired {
		t.Fatalf("err = %v", err)
	}
}

func TestPermissionWithMission(t *testing.T) {
	// §7.7.1: a permission request names its mission by mission_s256; a
	// terminated mission is a §8.8 error, here with an unregistered reason
	// the agent keeps as an opaque value.
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	terminated := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var p PermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.MissionS256 != mission {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}
		if terminated {
			WriteMissionTerminated(rw, "policy-review")
			return
		}
		writeJSON(t, rw, PermissionResponse{Permission: PermissionGranted})
	}))
	defer srv.Close()
	c := NewPSClient(srv.URL, testAgent(t))
	res, err := c.RequestPermission(context.Background(), PermissionRequest{Action: "BookHotel", MissionS256: mission})
	if err != nil || !res.Granted() {
		t.Fatalf("res %+v, err %v", res, err)
	}
	terminated = true
	_, err = c.RequestPermission(context.Background(), PermissionRequest{Action: "BookHotel", MissionS256: mission})
	var mse *MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != "policy-review" {
		t.Fatalf("err = %v", err)
	}
}

// TestAuditPermissionProblemErrors: problem responses other than a mission
// status error (e.g. mission_not_found, rate_limited) reach callers of
// Audit and RequestPermission as *ProblemError, with RetryAfter.
func TestAuditPermissionProblemErrors(t *testing.T) {
	agent := testAgent(t)
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/audit":
			WriteProblem(rw, http.StatusNotFound, "mission_not_found", "no such mission")
		case "/permission":
			rw.Header().Set(HeaderRetryAfter, "7")
			WriteProblem(rw, http.StatusTooManyRequests, "rate_limited", "")
		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()
	c := NewPSClient(srv.URL, agent)

	err := c.Audit(context.Background(), AuditRequest{MissionS256: mission, Action: "SendEmail"})
	var pe *ProblemError
	if !errors.As(err, &pe) || pe.Status != http.StatusNotFound || pe.Code != "mission_not_found" || pe.Detail != "no such mission" {
		t.Fatalf("Audit err = %v", err)
	}

	_, err = c.RequestPermission(context.Background(), PermissionRequest{Action: "BookHotel", MissionS256: mission})
	pe = nil
	if !errors.As(err, &pe) || pe.Status != http.StatusTooManyRequests || pe.Code != "rate_limited" || pe.RetryAfter != 7*time.Second {
		t.Fatalf("RequestPermission err = %v", err)
	}
}
