package personserver

import (
	"context"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// The library never decides policy. Every consent, permission, and mission
// decision goes through an interface the hosting application supplies,
// which answers allow, deny, or defer. A deferred request becomes a
// pending request (draft -11 §11.8) that the application resolves later —
// from its own approval UI, a notification the person taps, or an
// administrator queue — with [Server.Approve], [Server.Deny], or
// [Server.Ask].

// Outcome is the verdict of a [Decision].
type Outcome int

// Outcomes. The zero value denies, so a forgotten field fails closed.
const (
	Denied   Outcome = iota // refuse the request
	Allowed                 // grant it now, as the Grant says
	Deferred                // answer 202 and decide later
)

// Decision is a policy verdict on one request.
type Decision struct {
	Outcome Outcome
	// Grant qualifies an Allowed decision.
	Grant Grant
	// Code and Reason qualify a Denied decision. Code defaults to the
	// endpoint's denial: denied (§11.9.4) at the token endpoints, a 200
	// {"permission": "denied"} at the permission endpoint, and
	// interaction_unavailable at the interaction endpoint. Reason is a
	// human-readable detail (Markdown for a permission denial).
	Code   string
	Reason string
	// Requirement qualifies a Deferred decision: aauth.RequirementInteraction
	// (the person is directed to InteractionURL with a code), or
	// aauth.RequirementApproval (the PS reaches the person itself), or
	// aauth.RequirementClarification with Question. Empty means approval.
	Requirement string
	// Question is the clarification put to the agent (§7.5.1).
	Question *Question
	// RetryAfter is the polling interval to suggest, in seconds.
	RetryAfter int
}

// Grant is what an Allowed decision, or an approval of a pending request,
// grants. Each field applies to the request kinds named.
type Grant struct {
	// Person binds an unbound agent to this person (person and auth
	// tokens, missions; §13.14). It MUST equal an existing binding.
	Person string
	// Tenant is the person's organization, carried in person tokens.
	Tenant string
	// Scope is the scope an auth token grants; empty grants the resource
	// token's scope. It may not be broader than what was requested.
	Scope string
	// TTL caps the lifetime of the issued token (at most one hour).
	TTL time.Duration
	// Mission shapes an approved mission (mission proposals).
	Mission *MissionGrant
	// Answer is the person's answer to an interaction question.
	Answer string
}

// MissionGrant shapes the mission blob the PS approves (draft -11 §8.2).
// The approved mission MAY differ from the proposal.
type MissionGrant struct {
	// Description is the approved scope; empty keeps the proposal's.
	Description string
	// Tools are the approved_tools; nil keeps the proposal's, an empty
	// non-nil slice approves none.
	Tools []aauth.MissionTool
	// Resources are the approved_resources, for each of which the PS
	// issues a person token; nil keeps the proposal's.
	Resources []string
	// ExpiresAt, when set, is the mission's expires_at.
	ExpiresAt time.Time
	// Capabilities are those the PS can provide on the person's behalf now
	// (not part of the blob).
	Capabilities []string
	// Extra adds members to the blob; they become part of its identity.
	Extra map[string]any
}

// Question is a clarification question (draft -11 §7.5.1).
type Question struct {
	Text    string   `json:"clarification"`
	Options []string `json:"options,omitempty"`
	// Timeout is how long the recipient has to answer, in seconds; zero
	// means no deadline beyond the pending request's own.
	Timeout int `json:"timeout,omitempty"`
}

// Allow is an Allowed decision with g.
func Allow(g Grant) Decision { return Decision{Outcome: Allowed, Grant: g} }

// Deny is a Denied decision with the endpoint's default code.
func Deny(reason string) Decision { return Decision{Outcome: Denied, Reason: reason} }

// DeferInteraction defers with requirement=interaction: the agent directs
// the person to the PS's interaction page with a code (§11.6.3).
func DeferInteraction() Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementInteraction}
}

// DeferApproval defers with requirement=approval: the PS obtains the
// decision itself, by push, email, or an administrator (§11.6.4).
func DeferApproval() Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementApproval}
}

// DeferClarification defers by asking the agent a question (§7.5.1).
func DeferClarification(question string, options ...string) Decision {
	return Decision{Outcome: Deferred, Requirement: aauth.RequirementClarification,
		Question: &Question{Text: question, Options: options}}
}

// TokenRequest is a person token or auth token request awaiting a consent
// decision (draft -11 §7.1, §7.2). Everything in it has been verified,
// except the agent-asserted Hints.
type TokenRequest struct {
	// Kind is KindPersonToken or KindAuthToken.
	Kind Kind
	// Agent is the agent that signed the request; Subagent, when set, the
	// sub-agent the parent is requesting for (§10.2.3).
	Agent    *aauth.AgentClaims
	Subagent *aauth.AgentClaims
	// Person is the person the token would be issued for: the agent's
	// bound person, or the person behind the upstream token in call
	// chaining. Empty when the agent is not yet bound: the decision then
	// names the person in its Grant (typically after an interaction).
	Person string
	// Resource is the resource the token is for.
	Resource string
	// ResourceToken is the verified resource token (auth tokens only), and
	// Scope the scope it requests. AccessServer is its aud when the
	// resource has its own AS (four-party), else empty.
	ResourceToken *aauth.ResourceClaims
	Scope         string
	AccessServer  string
	// Mission is the mission the request is made under, if any.
	Mission *MissionRecord
	// Chained reports a call chaining request (an upstream_token was
	// verified, §10.1.1); Upstream is that token.
	Chained  bool
	Upstream aauth.PresentedToken
	// Capabilities are the agent's capabilities for this request, from the
	// request or, within a mission, from its approval (§7.1).
	Capabilities []string
	// Hints are the agent-asserted optional parameters (justification,
	// platform, device, ...). Present them as the agent's claims (§7.4).
	Hints aauth.TokenRequestHints
}

// Decider decides person token and auth token requests: whether this agent
// may act at the resource as the person, and with what scope (draft -11
// §7.1, §7.2, §7.4). A Deferred decision becomes a pending request.
type Decider interface {
	Decide(ctx context.Context, r *TokenRequest) (Decision, error)
}

// DeciderFunc adapts a function to [Decider].
type DeciderFunc func(ctx context.Context, r *TokenRequest) (Decision, error)

// Decide calls f.
func (f DeciderFunc) Decide(ctx context.Context, r *TokenRequest) (Decision, error) { return f(ctx, r) }
