package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ApprovedMission is a mission the PS approved (draft -11 §8.2), verified
// against its identifier.
type ApprovedMission struct {
	// S256 identifies the mission, with the PS, everywhere it appears: the
	// mission_s256 of tokens and PS requests.
	S256 string
	// Blob is the exact mission bytes S256 covers. Keep it: re-encoding
	// Mission would not reproduce the identifier.
	Blob []byte
	// Mission is the parsed blob.
	Mission *Mission
	// Capabilities the PS can provide on the person's behalf right now.
	Capabilities []string
	// PersonTokens maps approved resources to person tokens carrying
	// mission_s256; they are also cached for [PSClient.PersonToken].
	PersonTokens map[string]string
}

// ProposeMission proposes a mission at the PS's mission endpoint (draft -11
// §8.1) and follows the deferred response — review, clarification chat via
// OnClarification — to the approval (§8.2). The approval is verified
// before it is returned: the blob hashes to s256, names this agent, and
// carries its REQUIRED members; each person token is for the resource it
// is listed under, binds the agent's key, and carries mission_s256. The
// person tokens are added to the person token cache.
//
// The endpoint is [PSClient.MissionEndpoint], else BaseURL+"/mission".
func (c *PSClient) ProposeMission(ctx context.Context, p MissionProposal) (*ApprovedMission, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	if p.Description == "" {
		return nil, errors.New("aauth: MissionProposal.Description is required")
	}
	for _, r := range p.Resources {
		if err := ValidateServerIdentifier(r); err != nil {
			return nil, fmt.Errorf("aauth: MissionProposal.Resources: %w", err)
		}
	}
	res, err := c.post(ctx, c.endpoint(c.MissionEndpoint, "/mission"), p, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, endpointError("mission endpoint", res, readErrorBody(res))
	}
	var ma MissionApproval
	if err := json.NewDecoder(res.Body).Decode(&ma); err != nil {
		return nil, fmt.Errorf("aauth: mission endpoint: %w", err)
	}
	m, blob, err := ma.Decode()
	if err != nil {
		return nil, err
	}
	if m.Agent != c.Agent.ID.String() {
		return nil, fmt.Errorf("%w: mission is for agent %q, not %q", ErrUnexpectedToken, m.Agent, c.Agent.ID)
	}
	jkt := c.Agent.Thumbprint()
	for resource, tok := range ma.PersonTokens {
		pc, err := c.checkPersonToken(tok, resource, jkt)
		if err != nil {
			return nil, err
		}
		if pc.MissionS256 != ma.S256 {
			return nil, fmt.Errorf("%w: person token for %s carries mission_s256 %q", ErrUnexpectedToken, resource, pc.MissionS256)
		}
		c.storePersonToken(personCacheKey{boundJKT: jkt, resource: resource, mission: ma.S256}, tok, 0)
	}
	return &ApprovedMission{
		S256: ma.S256, Blob: blob, Mission: m, Capabilities: ma.Capabilities, PersonTokens: ma.PersonTokens,
	}, nil
}

// UpdateMission records a change in the work at the mission's URL (draft
// -11 §8.4) and returns the accepted update's s256. The PS may accept it
// at once or defer while the person reviews it. The mission itself — its
// blob and mission_s256 — is unchanged.
func (c *PSClient) UpdateMission(ctx context.Context, missionS256, description string) (*MissionUpdateResponse, error) {
	res, err := c.missionAction(ctx, missionS256, MissionAction{Action: MissionActionUpdate, Description: description})
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	var ur MissionUpdateResponse
	if err := json.NewDecoder(res.Body).Decode(&ur); err != nil {
		return nil, fmt.Errorf("aauth: mission update: %w", err)
	}
	return &ur, nil
}

// CompleteMission proposes that the mission is finished (draft -11 §8.5),
// following the deferred response while the person reviews the summary. A
// nil error means the person accepted and the PS terminated the mission as
// completed; follow-up questions arrive as clarifications.
func (c *PSClient) CompleteMission(ctx context.Context, missionS256, summary string) error {
	res, err := c.missionAction(ctx, missionS256, MissionAction{Action: MissionActionCompletion, Summary: summary})
	if err != nil {
		return err
	}
	drainBody(res.Body)
	return nil
}

// missionAction POSTs a to {mission_endpoint}/{missionS256} and returns
// the terminal 200 response. Failures are a [*MissionStatusError]
// (mission_terminated) or a [*ProblemError] (invalid_request,
// mission_not_found; §8.7).
func (c *PSClient) missionAction(ctx context.Context, missionS256 string, a MissionAction) (*http.Response, error) {
	if !ValidMissionS256(missionS256) {
		return nil, fmt.Errorf("aauth: %q is not a mission s256", missionS256)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	endpoint := c.endpoint(c.MissionEndpoint, "/mission") + "/" + url.PathEscape(missionS256)
	res, err := c.post(ctx, endpoint, a, true)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		defer closeBody(res.Body)
		return nil, endpointError("mission endpoint", res, readErrorBody(res))
	}
	return res, nil
}
