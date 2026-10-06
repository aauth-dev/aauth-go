package personserver

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"
)

// MemoryStore is an in-memory [Store] for tests and examples. It keeps
// everything in maps guarded by one mutex, copies records in and out (as a
// database would), and never prunes. Do not use it in production: state
// is lost on restart and is not shared between instances.
type MemoryStore struct {
	mu        sync.Mutex
	bindings  map[AgentRef]string
	subjects  map[[2]string]string // (resource, sub) → person
	agents    map[[2]string]AgentTokenRecord
	persons   map[string]PersonTokenRecord
	auths     map[[2]string]AuthTokenRecord
	revoked   map[[2]string]time.Time
	missions  map[string]MissionRecord
	logs      map[string][]MissionLogEntry
	pending   map[string][]byte // id → JSON
	codes     map[string]string // canonical code → id
	authOrder []([2]string)
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		bindings: map[AgentRef]string{},
		subjects: map[[2]string]string{},
		agents:   map[[2]string]AgentTokenRecord{},
		persons:  map[string]PersonTokenRecord{},
		auths:    map[[2]string]AuthTokenRecord{},
		revoked:  map[[2]string]time.Time{},
		missions: map[string]MissionRecord{},
		logs:     map[string][]MissionLogEntry{},
		pending:  map[string][]byte{},
		codes:    map[string]string{},
	}
}

var _ Store = (*MemoryStore)(nil)

// BoundPerson implements BindingStore.
func (m *MemoryStore) BoundPerson(_ context.Context, agent AgentRef) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.bindings[agent]
	if !ok {
		return "", ErrNotFound
	}
	return p, nil
}

// Bind implements BindingStore.
func (m *MemoryStore) Bind(_ context.Context, agent AgentRef, person string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.bindings[agent]; ok && p != person {
		return ErrBindingConflict
	}
	m.bindings[agent] = person
	return nil
}

// Unbind implements BindingStore.
func (m *MemoryStore) Unbind(_ context.Context, agent AgentRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bindings, agent)
	return nil
}

// RecordSubject implements SubjectStore.
func (m *MemoryStore) RecordSubject(_ context.Context, resource, sub, person string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subjects[[2]string{resource, sub}] = person
	return nil
}

// SubjectPerson implements SubjectStore.
func (m *MemoryStore) SubjectPerson(_ context.Context, resource, sub string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.subjects[[2]string{resource, sub}]
	if !ok {
		return "", ErrNotFound
	}
	return p, nil
}

// RecordAgentToken implements TokenStore.
func (m *MemoryStore) RecordAgentToken(_ context.Context, r AgentTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[[2]string{r.Issuer, r.JTI}] = r
	return nil
}

// AgentToken implements TokenStore.
func (m *MemoryStore) AgentToken(_ context.Context, iss, jti string) (*AgentTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.agents[[2]string{iss, jti}]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

// RecordPersonToken implements TokenStore.
func (m *MemoryStore) RecordPersonToken(_ context.Context, r PersonTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.PresentedTo = slices.Clone(r.PresentedTo)
	m.persons[r.JTI] = r
	return nil
}

// PersonToken implements TokenStore.
func (m *MemoryStore) PersonToken(_ context.Context, jti string) (*PersonTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.persons[jti]
	if !ok {
		return nil, ErrNotFound
	}
	r.PresentedTo = slices.Clone(r.PresentedTo)
	return &r, nil
}

// PersonTokensForSubject implements TokenStore.
func (m *MemoryStore) PersonTokensForSubject(_ context.Context, resource, sub string) ([]PersonTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PersonTokenRecord
	for _, r := range m.persons {
		if r.Resource == resource && r.Subject == sub {
			r.PresentedTo = slices.Clone(r.PresentedTo)
			out = append(out, r)
		}
	}
	return out, nil
}

// MarkPresented implements TokenStore.
func (m *MemoryStore) MarkPresented(_ context.Context, jti, as string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.persons[jti]
	if !ok {
		return ErrNotFound
	}
	if !slices.Contains(r.PresentedTo, as) {
		r.PresentedTo = append(slices.Clone(r.PresentedTo), as)
		m.persons[jti] = r
	}
	return nil
}

// RecordAuthToken implements TokenStore.
func (m *MemoryStore) RecordAuthToken(_ context.Context, r AuthTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{r.Issuer, r.JTI}
	if _, ok := m.auths[k]; !ok {
		m.authOrder = append(m.authOrder, k)
	}
	m.auths[k] = r
	return nil
}

// AuthToken implements TokenStore.
func (m *MemoryStore) AuthToken(_ context.Context, iss, jti string) (*AuthTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.auths[[2]string{iss, jti}]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

// TokensForAgent implements TokenStore.
func (m *MemoryStore) TokensForAgent(_ context.Context, agent AgentRef) ([]PersonTokenRecord, []AuthTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ps []PersonTokenRecord
	for _, r := range m.persons {
		if r.Agent == agent || r.Subagent == agent {
			r.PresentedTo = slices.Clone(r.PresentedTo)
			ps = append(ps, r)
		}
	}
	return ps, m.authsWhere(func(r AuthTokenRecord) bool { return r.Agent == agent || r.Subagent == agent }), nil
}

// PersonTokensFromUpstream implements TokenStore.
func (m *MemoryStore) PersonTokensFromUpstream(_ context.Context, iss, jti string) ([]PersonTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PersonTokenRecord
	for _, r := range m.persons {
		if r.UpstreamIssuer == iss && r.UpstreamJTI == jti {
			r.PresentedTo = slices.Clone(r.PresentedTo)
			out = append(out, r)
		}
	}
	return out, nil
}

// AuthTokensForPersonToken implements TokenStore.
func (m *MemoryStore) AuthTokensForPersonToken(_ context.Context, jti string) ([]AuthTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authsWhere(func(r AuthTokenRecord) bool { return r.PersonJTI == jti }), nil
}

// AuthTokensForMission implements TokenStore.
func (m *MemoryStore) AuthTokensForMission(_ context.Context, s256 string) ([]AuthTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authsWhere(func(r AuthTokenRecord) bool { return r.MissionS256 == s256 }), nil
}

// authsWhere lists auth token records in insertion order; m.mu is held.
func (m *MemoryStore) authsWhere(keep func(AuthTokenRecord) bool) []AuthTokenRecord {
	var out []AuthTokenRecord
	for _, k := range m.authOrder {
		if r := m.auths[k]; keep(r) {
			out = append(out, r)
		}
	}
	return out
}

// Revoke implements TokenStore.
func (m *MemoryStore) Revoke(_ context.Context, iss, jti string, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[[2]string{iss, jti}] = exp
	return nil
}

// IsRevoked implements TokenStore.
func (m *MemoryStore) IsRevoked(_ context.Context, iss, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[[2]string{iss, jti}]
	return ok, nil
}

// CreateMission implements MissionStore.
func (m *MemoryStore) CreateMission(_ context.Context, r *MissionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.missions[r.S256]; ok {
		return ErrExists
	}
	c := *r
	c.Blob, c.Capabilities = slices.Clone(r.Blob), slices.Clone(r.Capabilities)
	m.missions[r.S256] = c
	return nil
}

// Mission implements MissionStore.
func (m *MemoryStore) Mission(_ context.Context, s256 string) (*MissionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.missions[s256]
	if !ok {
		return nil, ErrNotFound
	}
	r.Blob, r.Capabilities = slices.Clone(r.Blob), slices.Clone(r.Capabilities)
	return &r, nil
}

// TerminateMission implements MissionStore.
func (m *MemoryStore) TerminateMission(_ context.Context, s256, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.missions[s256]
	if !ok {
		return ErrNotFound
	}
	if r.Status != MissionTerminated {
		r.Status, r.TerminationReason = MissionTerminated, reason
		m.missions[s256] = r
	}
	return nil
}

// AppendMissionLog implements MissionStore.
func (m *MemoryStore) AppendMissionLog(_ context.Context, s256 string, e MissionLogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.missions[s256]; !ok {
		return ErrNotFound
	}
	e.Body = slices.Clone(e.Body)
	m.logs[s256] = append(m.logs[s256], e)
	return nil
}

// MissionLog implements MissionStore.
func (m *MemoryStore) MissionLog(_ context.Context, s256 string) ([]MissionLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.missions[s256]; !ok {
		return nil, ErrNotFound
	}
	return slices.Clone(m.logs[s256]), nil
}

// CreatePending implements PendingStore.
func (m *MemoryStore) CreatePending(_ context.Context, p *Pending) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[p.ID]; ok {
		return ErrExists
	}
	p.Version = 1
	return m.putPending(p)
}

// Pending implements PendingStore.
func (m *MemoryStore) Pending(_ context.Context, id string) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getPending(id)
}

// PendingByCode implements PendingStore.
func (m *MemoryStore) PendingByCode(_ context.Context, code string) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.codes[code]
	if !ok {
		return nil, ErrNotFound
	}
	return m.getPending(id)
}

// UpdatePending implements PendingStore.
func (m *MemoryStore) UpdatePending(_ context.Context, p *Pending) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, err := m.getPending(p.ID)
	if err != nil {
		return err
	}
	if cur.Version != p.Version {
		return ErrConflict
	}
	p.Version++
	return m.putPending(p)
}

// PendingForResourceToken implements PendingStore.
func (m *MemoryStore) PendingForResourceToken(_ context.Context, iss, jti string) ([]*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Pending
	for id := range m.pending {
		p, err := m.getPending(id)
		if err != nil {
			return nil, err
		}
		if p.Open() && p.ResourceTokenIssuer == iss && p.ResourceTokenJTI == jti {
			out = append(out, p)
		}
	}
	return out, nil
}

// putPending stores a copy of p; m.mu is held.
func (m *MemoryStore) putPending(p *Pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	m.pending[p.ID] = b
	if p.CodeCanonical != "" {
		m.codes[p.CodeCanonical] = p.ID
	}
	return nil
}

// getPending returns a copy of pending id; m.mu is held.
func (m *MemoryStore) getPending(id string) (*Pending, error) {
	b, ok := m.pending[id]
	if !ok {
		return nil, ErrNotFound
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
