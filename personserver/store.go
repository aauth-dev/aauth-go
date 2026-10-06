package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Storage is supplied by the caller through the [Store] interface, so a
// hosting application keeps PS state wherever it keeps the rest of its
// data. The interfaces are small and record-oriented; [NewMemoryStore] is a
// reference implementation for tests and examples, not for production.

// Store errors. Implementations return these (or wrap them) so the server
// can tell an absent record from a failure to reach storage.
var (
	// ErrNotFound means no record exists for the key.
	ErrNotFound = errors.New("personserver: not found")
	// ErrConflict means an optimistic update lost a race: the record's
	// Version changed since it was read.
	ErrConflict = errors.New("personserver: version conflict")
	// ErrBindingConflict means the agent is already bound to a different
	// person (draft -11 §13.14: once established, the PS MUST NOT allow a
	// different person to claim the same agent).
	ErrBindingConflict = errors.New("personserver: agent is bound to another person")
	// ErrExists means a record with the key already exists.
	ErrExists = errors.New("personserver: already exists")
)

// AgentRef identifies an agent the way a PS recognizes it: by its agent
// token's (iss, sub) (draft -11 §13.14).
type AgentRef struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
}

// String renders the pair as "sub (iss)".
func (a AgentRef) String() string { return a.Subject + " (" + a.Issuer + ")" }

// IsZero reports whether a names no agent.
func (a AgentRef) IsZero() bool { return a.Issuer == "" && a.Subject == "" }

// Store is everything the PS persists. A hosting application implements it
// over its own database; see [NewMemoryStore] for the reference semantics.
type Store interface {
	BindingStore
	SubjectStore
	TokenStore
	MissionStore
	PendingStore
}

// BindingStore holds the agent-person binding (draft -11 §13.14): each
// agent, identified by (iss, sub), is associated with exactly one person.
// Person identifiers are the hosting application's own and opaque to the
// library.
type BindingStore interface {
	// BoundPerson returns the person agent is bound to, or ErrNotFound.
	BoundPerson(ctx context.Context, agent AgentRef) (string, error)
	// Bind binds agent to person. Binding an agent to the person it is
	// already bound to succeeds; binding it to another person MUST fail
	// with ErrBindingConflict.
	Bind(ctx context.Context, agent AgentRef, person string) error
	// Unbind removes agent's binding (revoking it); a later Bind may bind
	// the agent to a different person. Unbinding an unbound agent succeeds.
	Unbind(ctx context.Context, agent AgentRef) error
}

// SubjectStore records the directed identifiers the PS minted (draft -11
// §7.1, §14.1), so it can resolve the person behind an upstream token's
// (aud, sub) in call chaining.
type SubjectStore interface {
	// RecordSubject records that sub is person's directed identifier at
	// resource. Recording the same triple again succeeds.
	RecordSubject(ctx context.Context, resource, sub, person string) error
	// SubjectPerson returns the person whose directed identifier at
	// resource is sub, or ErrNotFound.
	SubjectPerson(ctx context.Context, resource, sub string) (string, error)
}

// AgentTokenRecord is an agent token the PS accepted (draft -11 §11.12.4:
// the PS records each agent token's (iss, jti) and the sub it carried until
// its exp plus clock skew), so an agent provider's revocation cascades by
// agent identity.
type AgentTokenRecord struct {
	Issuer  string    `json:"iss"`
	JTI     string    `json:"jti"`
	Subject string    `json:"sub"`
	Exp     time.Time `json:"exp"`
}

// PersonTokenRecord is a person token the PS issued (draft -11 §7.1
// retention, §11.12.4).
type PersonTokenRecord struct {
	JTI      string    `json:"jti"`
	Resource string    `json:"aud"` // the token's aud
	Exp      time.Time `json:"exp"`
	Agent    AgentRef  `json:"agent"`              // the agent that requested it
	Subagent AgentRef  `json:"subagent,omitempty"` // the sub-agent whose key it binds, if any
	Person   string    `json:"person"`
	Subject  string    `json:"sub"`
	// MissionS256 is the mission the token was issued under.
	MissionS256 string `json:"mission_s256,omitempty"`
	// UpstreamIssuer and UpstreamJTI name the upstream token of a call
	// chaining request (§10.1.1), so revoking it walks the chain.
	UpstreamIssuer string `json:"upstream_iss,omitempty"`
	UpstreamJTI    string `json:"upstream_jti,omitempty"`
	// PresentedTo lists the access servers the PS presented the token to
	// (§9.1.1); it is revoked there too.
	PresentedTo []string `json:"presented_to,omitempty"`
}

// AuthTokenRecord is an auth token the PS issued (three-party) or obtained
// by federation (four-party) (draft -11 §11.12.4).
type AuthTokenRecord struct {
	Issuer   string    `json:"iss"` // the PS, or the AS it federated with
	JTI      string    `json:"jti"`
	Resource string    `json:"aud"`
	Exp      time.Time `json:"exp"`
	// PresentedJTI is the jti of the token the request presented, and
	// PersonJTI the person token at the root of the grant.
	PresentedJTI string   `json:"presented_jti"`
	PersonJTI    string   `json:"person_jti"`
	Agent        AgentRef `json:"agent"`
	Subagent     AgentRef `json:"subagent,omitempty"`
	Person       string   `json:"person"`
	Subject      string   `json:"sub"`
	MissionS256  string   `json:"mission_s256,omitempty"`
}

// TokenStore keeps the records revocation needs: the tokens the PS
// accepted and issued, and the revocations it received or made, keyed by
// (iss, jti) (draft -11 §11.12.1).
type TokenStore interface {
	RecordAgentToken(ctx context.Context, r AgentTokenRecord) error
	// AgentToken returns the accepted agent token (iss, jti), or
	// ErrNotFound.
	AgentToken(ctx context.Context, iss, jti string) (*AgentTokenRecord, error)

	RecordPersonToken(ctx context.Context, r PersonTokenRecord) error
	// PersonToken returns the issued person token jti, or ErrNotFound.
	PersonToken(ctx context.Context, jti string) (*PersonTokenRecord, error)
	// PersonTokensForSubject returns the person tokens issued for the
	// directed identifier sub at resource.
	PersonTokensForSubject(ctx context.Context, resource, sub string) ([]PersonTokenRecord, error)
	// MarkPresented records that the person token jti was presented to the
	// access server as (§9.1.1).
	MarkPresented(ctx context.Context, jti, as string) error

	RecordAuthToken(ctx context.Context, r AuthTokenRecord) error
	// AuthToken returns the auth token (iss, jti), or ErrNotFound.
	AuthToken(ctx context.Context, iss, jti string) (*AuthTokenRecord, error)

	// TokensForAgent returns the person and auth tokens issued to agent,
	// as the requesting agent or as the sub-agent they bind (§11.12.4: the
	// cascade is by agent identity).
	TokensForAgent(ctx context.Context, agent AgentRef) ([]PersonTokenRecord, []AuthTokenRecord, error)
	// PersonTokensFromUpstream returns the person tokens issued with the
	// upstream token (iss, jti).
	PersonTokensFromUpstream(ctx context.Context, iss, jti string) ([]PersonTokenRecord, error)
	// AuthTokensForPersonToken returns the auth tokens whose grant is
	// rooted in the person token jti.
	AuthTokensForPersonToken(ctx context.Context, jti string) ([]AuthTokenRecord, error)
	// AuthTokensForMission returns the auth tokens issued under the
	// mission s256.
	AuthTokensForMission(ctx context.Context, s256 string) ([]AuthTokenRecord, error)

	// Revoke records the revocation of (iss, jti), remembered until exp
	// (plus clock skew). Revoking again succeeds.
	Revoke(ctx context.Context, iss, jti string, exp time.Time) error
	// IsRevoked reports whether (iss, jti) was revoked.
	IsRevoked(ctx context.Context, iss, jti string) (bool, error)
}

// Mission states (draft -11 §8.6).
const (
	MissionActive     = "active"
	MissionTerminated = "terminated"
)

// MissionRecord is an approved mission (draft -11 §8.2). Blob is the exact
// bytes S256 covers; the PS serves those same bytes wherever it later
// exposes the mission.
type MissionRecord struct {
	S256  string   `json:"s256"`
	Blob  []byte   `json:"blob"`
	Owner AgentRef `json:"owner"` // the agent that proposed it
	// Person is the person who approved it.
	Person string `json:"person"`
	// Status is MissionActive or MissionTerminated; a terminated mission
	// never returns to active.
	Status string `json:"status"`
	// TerminationReason records why it terminated (§8.6), outside the
	// immutable blob.
	TerminationReason string    `json:"termination_reason,omitempty"`
	ApprovedAt        time.Time `json:"approved_at"`
	// ExpiresAt is the blob's expires_at, zero when it has none.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Capabilities the PS reported at approval (§8.2).
	Capabilities []string `json:"capabilities,omitempty"`
}

// Mission log entry kinds (draft -11 §8.3).
const (
	LogTokenRequest  = "token_request"
	LogUpdate        = "update"
	LogCompletion    = "completion"
	LogPermission    = "permission"
	LogAudit         = "audit"
	LogInteraction   = "interaction"
	LogClarification = "clarification"
	LogTermination   = "termination"
)

// MissionLogEntry is one entry of a mission's log (draft -11 §8.3): an
// ordered record of the agent's actions and the supervision decisions.
type MissionLogEntry struct {
	Time  time.Time `json:"time"`
	Kind  string    `json:"kind"`
	Agent AgentRef  `json:"agent,omitzero"`
	// Body is the entry's content: the request or the decision, as JSON.
	// For an accepted update it is the exact update bytes S256 covers.
	Body json.RawMessage `json:"body,omitempty"`
	// S256 is set on accepted updates (§8.4).
	S256 string `json:"s256,omitempty"`
}

// MissionStore persists missions and their logs (draft -11 §8).
type MissionStore interface {
	// CreateMission stores a newly approved mission; ErrExists if S256 is
	// already taken.
	CreateMission(ctx context.Context, m *MissionRecord) error
	// Mission returns the mission s256, or ErrNotFound. The lookup SHOULD
	// cost the same whether or not the mission exists: the server compares
	// ownership after it in constant time so that a missing mission and
	// another agent's mission are answered alike (§8.7).
	Mission(ctx context.Context, s256 string) (*MissionRecord, error)
	// TerminateMission marks the mission terminated with reason. A
	// terminated mission stays terminated (its first reason is kept).
	TerminateMission(ctx context.Context, s256, reason string) error
	// AppendMissionLog appends e to the mission's log.
	AppendMissionLog(ctx context.Context, s256 string, e MissionLogEntry) error
	// MissionLog returns the log in order.
	MissionLog(ctx context.Context, s256 string) ([]MissionLogEntry, error)
}

// PendingStore persists deferred requests (draft -11 §11.8). Updates are
// optimistic: UpdatePending succeeds only when the stored Version equals
// the given record's Version, and then increments it.
type PendingStore interface {
	// CreatePending stores a new pending request (Version 1).
	CreatePending(ctx context.Context, p *Pending) error
	// Pending returns the pending request id, or ErrNotFound.
	Pending(ctx context.Context, id string) (*Pending, error)
	// PendingByCode returns the pending request whose canonical
	// interaction code is code, or ErrNotFound.
	PendingByCode(ctx context.Context, code string) (*Pending, error)
	// UpdatePending replaces p if its Version matches (ErrConflict
	// otherwise) and increments p.Version.
	UpdatePending(ctx context.Context, p *Pending) error
	// PendingForResourceToken returns the unresolved pending requests
	// started for the resource token (iss, jti) (§11.12.4).
	PendingForResourceToken(ctx context.Context, iss, jti string) ([]*Pending, error)
}
