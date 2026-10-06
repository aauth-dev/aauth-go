package accessserver

import (
	"context"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// The library never decides resource policy: every token request goes to
// the hosting application's [Authorizer], which allows, denies, asks for
// claims, or defers (draft -11 §9.3.2 describes the kinds of policy an AS
// applies). A deferred request becomes a pending request the PS polls,
// resolved later with [Server.Approve], [Server.Deny], or [Server.Ask].

// Outcome is the verdict of a [Decision].
type Outcome int

// Outcomes. The zero value denies.
const (
	Denied   Outcome = iota // refuse: 403 denied, or Code
	Allowed                 // issue the auth token
	Deferred                // answer 202 and decide later
)

// Decision is the Authorizer's verdict on a token request.
type Decision struct {
	Outcome Outcome
	// Scope is the granted scope (Allowed); empty grants the resource
	// token's scope. It may not be broader than the request.
	Scope string
	// TTL caps the auth token's lifetime (at most one hour).
	TTL time.Duration
	// Requirement qualifies a Deferred decision:
	// aauth.RequirementClaims with RequiredClaims (§9.2),
	// aauth.RequirementInteraction (the person goes to InteractionURL),
	// aauth.RequirementClarification with Question, or
	// aauth.RequirementApproval (the default).
	Requirement    string
	RequiredClaims []string
	Question       *Question
	RetryAfter     int
	// Code and Reason qualify a Denied decision; Code defaults to denied.
	Code   string
	Reason string
}

// Question is a clarification for the PS (draft -11 §7.5.1).
type Question struct {
	Text    string   `json:"clarification"`
	Options []string `json:"options,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

// Allow grants scope (empty: the requested scope).
func Allow(scope string) Decision { return Decision{Outcome: Allowed, Scope: scope} }

// Deny refuses with denied.
func Deny(reason string) Decision { return Decision{Outcome: Denied, Reason: reason} }

// RequireClaims asks the PS for identity claims (draft -11 §9.2). sub is
// never requested: the presented token already identifies the person.
func RequireClaims(names ...string) Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementClaims, RequiredClaims: names}
}

// DeferInteraction defers until the person completes an interaction at
// the AS — for example binding their PS at the AS (§9.3.1).
func DeferInteraction() Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementInteraction}
}

// DeferApproval defers while the AS obtains approval itself (§11.6.4).
func DeferApproval() Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementApproval}
}

// DeferClarification asks the PS a question (§7.5.1).
func DeferClarification(question string, options ...string) Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementClarification, Question: &Question{Text: question, Options: options}}
}

// AuthorizationRequest is a verified PS-to-AS token request (draft -11
// §9.1.1).
type AuthorizationRequest struct {
	// PS is the person server that signed the request.
	PS string
	// Agent is the agent token (the parent's, for a sub-agent grant), and
	// Subagent the sub-agent the token will bind. Agent tokens may carry
	// posture claims bearing on policy (§9.1.1).
	Agent    *aauth.AgentClaims
	Subagent *aauth.AgentClaims
	// Resource is the verified resource token: the resource, the person
	// (ps, sub), the requested scope, account, and mission.
	Resource *aauth.ResourceClaims
	// Presented is the verified presented token.
	Presented aauth.PresentedToken
	// Upstream is the verified upstream token of a call chaining request.
	Upstream aauth.PresentedToken
	// Claims are the identity claims the PS supplied after a
	// requirement=claims (§9.2), nil before.
	Claims map[string]any
	// Transcript holds the PS's answers to earlier clarifications.
	Transcript []Exchange
}

// Exchange is one clarification round with the PS.
type Exchange struct {
	Time     time.Time `json:"time"`
	Question string    `json:"question"`
	Answer   string    `json:"answer,omitempty"`
	Updated  bool      `json:"updated,omitempty"`
}

// Authorizer decides token requests at the AS.
type Authorizer interface {
	Authorize(ctx context.Context, r *AuthorizationRequest) (Decision, error)
}

// AuthorizerFunc adapts a function to [Authorizer].
type AuthorizerFunc func(ctx context.Context, r *AuthorizationRequest) (Decision, error)

// Authorize calls f.
func (f AuthorizerFunc) Authorize(ctx context.Context, r *AuthorizationRequest) (Decision, error) {
	return f(ctx, r)
}
