package personserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	aauth "github.com/aauth-dev/aauth-go"
)

// Mission state checks shared by every endpoint that takes a mission_s256
// (draft -11 §8.6–§8.8). Every decision path that acts on a mission
// compares the current time to its expires_at and treats a mission past it
// as terminated with reason expired.

// errMissionNotFound is the uniform answer for a mission that does not
// exist or is not the caller's (§8.7).
var errMissionNotFound = problem(http.StatusNotFound, aauth.ErrCodeMissionNotFound, "no such mission")

// dummyOwner is compared against when a mission does not exist, so the
// not-found path does the same work as the not-owner path (§8.7).
var dummyOwner = AgentRef{Issuer: "https://invalid.invalid", Subject: "aauth:none@invalid.invalid"}

// ownedMission returns the mission s256 if it exists and is owner's, with
// errMissionNotFound otherwise — the same status, body, and headers, and
// equivalent work, whether it does not exist or belongs to another agent
// (§8.7). A terminated (or expired) mission of the owner is a
// *aauth.MissionStatusError.
func (s *Server) ownedMission(ctx context.Context, s256 string, owner AgentRef) (*MissionRecord, error) {
	if !aauth.ValidMissionS256(s256) {
		return nil, errMissionNotFound
	}
	m, err := s.cfg.Store.Mission(ctx, s256)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, storeErr("load mission", err)
	}
	have := dummyOwner
	if err == nil {
		have = m.Owner
	}
	// Constant-time comparison of the owner in both branches.
	match := subtle.ConstantTimeCompare([]byte(have.Issuer+"\x00"+have.Subject), []byte(owner.Issuer+"\x00"+owner.Subject)) == 1
	if err != nil || !match {
		s.logger().WarnContext(ctx, "personserver: mission lookup failed",
			"agent", owner.String(), "mission_hash", refHash(s256))
		return nil, errMissionNotFound
	}
	return s.liveMission(ctx, m)
}

// activeMission returns the mission s256 that a verified token names, with
// no ownership check (the PS issued the token that carries it). A missing
// mission is invalid; a terminated one is a *aauth.MissionStatusError.
func (s *Server) activeMission(ctx context.Context, s256 string) (*MissionRecord, error) {
	m, err := s.cfg.Store.Mission(ctx, s256)
	if errors.Is(err, ErrNotFound) {
		return nil, &aauth.MissionStatusError{Code: aauth.MissionErrTerminated, MissionStatus: aauth.MissionStatusTerminated}
	}
	if err != nil {
		return nil, storeErr("load mission", err)
	}
	return s.liveMission(ctx, m)
}

// liveMission fails with a mission status error unless m is active and
// before its expires_at; a mission found past it is terminated as expired.
func (s *Server) liveMission(ctx context.Context, m *MissionRecord) (*MissionRecord, error) {
	if m.Status == MissionActive && !m.ExpiresAt.IsZero() && !s.now().Before(m.ExpiresAt) {
		if err := s.cfg.Store.TerminateMission(ctx, m.S256, aauth.TerminationExpired); err != nil {
			return nil, storeErr("terminate mission", err)
		}
		s.missionLog(ctx, m.S256, LogTermination, AgentRef{}, map[string]string{"reason": aauth.TerminationExpired})
		m.Status, m.TerminationReason = MissionTerminated, aauth.TerminationExpired
	}
	if m.Status != MissionActive {
		return nil, &aauth.MissionStatusError{
			Code: aauth.MissionErrTerminated, MissionStatus: aauth.MissionStatusTerminated, TerminationReason: m.TerminationReason,
		}
	}
	return m, nil
}

// checkMission is the PS's mission check on a resource token (§6.7.2
// step 4): the mission is active and before its expires_at.
func (s *Server) checkMission(ctx context.Context, s256 string) error {
	_, err := s.activeMission(ctx, s256)
	return err
}

// missionLog appends an entry to the mission's log (§8.3); a failure is
// logged, not returned, since the request it records has been handled.
func (s *Server) missionLog(ctx context.Context, s256, kind string, agent AgentRef, body any) {
	if s256 == "" {
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		s.logger().ErrorContext(ctx, "personserver: mission log entry", "error", err)
		return
	}
	if err := s.cfg.Store.AppendMissionLog(ctx, s256, MissionLogEntry{Time: s.now(), Kind: kind, Agent: agent, Body: raw}); err != nil {
		s.logger().ErrorContext(ctx, "personserver: append mission log", "error", err)
	}
}

// refHash is a short digest of a mission reference for security logs,
// which SHOULD NOT retain raw references from failed requests (§8.7).
func refHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:6])
}
