package aauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMissionStatusErrorReasons(t *testing.T) {
	tests := []struct {
		reason    string
		known     bool
		repropose bool
	}{
		{TerminationExpired, true, true},
		{TerminationRevoked, true, false},
		{TerminationCompleted, true, false},
		{TerminationSuperseded, true, false},
		{TerminationAdministrative, true, false},
		{"", false, false},
		{"quota_exhausted", false, false}, // open set: opaque, invites nothing
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("reason=%q", tc.reason), func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteMissionTerminated(rec, tc.reason)
			mse := missionStatusErrorFrom(rec.Code, rec.Body.Bytes())
			if mse == nil {
				t.Fatalf("status %d body %s: not a mission status error", rec.Code, rec.Body)
			}
			if mse.MissionStatus != MissionStatusTerminated || mse.TerminationReason != tc.reason {
				t.Fatalf("decoded %+v", mse)
			}
			if got := KnownTerminationReason(tc.reason); got != tc.known {
				t.Fatalf("KnownTerminationReason = %v, want %v", got, tc.known)
			}
			if got := mse.Repropose(); got != tc.repropose {
				t.Fatalf("Repropose = %v, want %v", got, tc.repropose)
			}
			var target *MissionStatusError
			if !errors.As(fmt.Errorf("wrapped: %w", mse), &target) {
				t.Fatal("errors.As failed")
			}
		})
	}
	if missionStatusErrorFrom(http.StatusBadRequest, []byte(`{"error":"mission_terminated"}`)) != nil {
		t.Fatal("non-403 decoded as a mission status error")
	}
}
