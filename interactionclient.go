package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Interaction request types (draft -11 §7.6.1). Proposing mission
// completion is not among them; it belongs at the mission endpoint (§8.5).
const (
	InteractionTypeInteraction = "interaction" // relay an interaction URL and code to the user
	InteractionTypePayment     = "payment"     // relay a payment approval
	InteractionTypeQuestion    = "question"    // ask the user a question
)

// InteractionRequest is the body of POST {interaction_endpoint} (draft -11
// §7.6.1): the agent's channel to the user through the PS, with or without
// a mission.
type InteractionRequest struct {
	// Type is InteractionTypeInteraction, InteractionTypePayment, or
	// InteractionTypeQuestion. REQUIRED.
	Type string `json:"type"`
	// Description is Markdown context for the user.
	Description string `json:"description,omitempty"`
	// URL and Code are the interaction URL and code to relay (interaction
	// and payment types).
	URL  string `json:"url,omitempty"`
	Code string `json:"code,omitempty"`
	// MaxWait is the most seconds the PS SHOULD hold the relay's deferred
	// response before resolving it (interaction and payment types).
	MaxWait int `json:"max_wait,omitempty"`
	// Question is the Markdown question for the user (question type).
	Question string `json:"question,omitempty"`
	// MissionS256 names the mission the request belongs to.
	MissionS256 string `json:"mission_s256,omitempty"`
}

// InteractionResponse is the terminal 200 body of the interaction
// endpoint (§7.6.2): for the question type, the user's answer.
type InteractionResponse struct {
	Answer string `json:"answer,omitempty"`
}

// RequestInteraction posts to the PS's interaction endpoint (draft -11
// §7.6) and follows its deferred response to a terminal one:
//
//   - question: the PS asks the user and returns the answer.
//   - interaction, payment: the PS relays the URL and code to the user.
//     When the URL is hosted by the PS itself, its terminal response is
//     authoritative. When it is a resource's, the resource's pending URL
//     is: the relay resolves once the user has engaged (or MaxWait
//     elapses), and the agent keeps polling the resource (§7.6.2).
//
// An error matching [ErrInteractionUnavailable] (424) means the PS has no
// channel to the user; the agent directs the user itself (§11.6.3.2).
// user_unreachable (§11.9.3) and the polling errors (§11.9.4) are terminal
// [*ProblemError]s; a terminated mission is a [*MissionStatusError] (§8.8).
//
// The endpoint is [PSClient.InteractionEndpoint], else
// BaseURL+"/interaction".
func (c *PSClient) RequestInteraction(ctx context.Context, ir InteractionRequest) (*InteractionResponse, error) {
	switch ir.Type {
	case InteractionTypeInteraction, InteractionTypePayment:
		if ir.URL == "" {
			return nil, fmt.Errorf("aauth: InteractionRequest of type %s needs a URL to relay", ir.Type)
		}
	case InteractionTypeQuestion:
		if ir.Question == "" {
			return nil, errors.New("aauth: InteractionRequest of type question needs a Question")
		}
	default:
		return nil, fmt.Errorf("aauth: InteractionRequest.Type %q is not interaction, payment, or question", ir.Type)
	}
	res, err := c.post(ctx, c.endpoint(c.InteractionEndpoint, "/interaction"), ir, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode/100 != 2 {
		return nil, endpointError("interaction endpoint", res, readErrorBody(res))
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}
	var out InteractionResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("aauth: interaction endpoint: %w", err)
		}
	}
	return &out, nil
}

// RelayInteraction relays a resource's requirement=interaction (draft -11
// §11.6.3.2) to the user through the PS: an interaction request carrying
// the requirement's URL and code. On [ErrInteractionUnavailable] the agent
// directs the user to {url}?code={code} itself. Either way the resource's
// pending URL remains authoritative for completion (§7.6.2).
func (c *PSClient) RelayInteraction(ctx context.Context, r Requirement, description, missionS256 string) (*InteractionResponse, error) {
	if r.Requirement != RequirementInteraction {
		return nil, fmt.Errorf("aauth: RelayInteraction needs requirement=interaction, got %q", r.Requirement)
	}
	return c.RequestInteraction(ctx, InteractionRequest{
		Type: InteractionTypeInteraction, URL: r.URL, Code: r.Code,
		Description: description, MissionS256: missionS256,
	})
}
