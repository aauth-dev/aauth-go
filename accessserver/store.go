package accessserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
)

// Store errors.
var (
	// ErrNotFound means no record exists for the key.
	ErrNotFound = errors.New("accessserver: not found")
	// ErrConflict means an optimistic update lost a race.
	ErrConflict = errors.New("accessserver: version conflict")
	// ErrExists means a record with the key already exists.
	ErrExists = errors.New("accessserver: already exists")
)

// AuthTokenRecord is an auth token the AS issued (draft -11 §11.12.4: an
// AS records each auth token with the presented token it was issued
// against).
type AuthTokenRecord struct {
	JTI      string    `json:"jti"`
	Resource string    `json:"aud"`
	Exp      time.Time `json:"exp"`
	// PS is the person server that requested it.
	PS string `json:"ps"`
	// PresentedIssuer and PresentedJTI name the presented token: a person
	// token from the PS, or an auth token from this AS on a step-up.
	PresentedIssuer string `json:"presented_iss"`
	PresentedJTI    string `json:"presented_jti"`
	// Agent is the agent token's sub (the parent, for a sub-agent grant).
	Agent       string `json:"agent"`
	Subject     string `json:"sub"`
	Scope       string `json:"scope,omitempty"`
	MissionS256 string `json:"mission_s256,omitempty"`
}

// Store is everything the AS persists.
type Store interface {
	// RecordAuthToken records an issued auth token.
	RecordAuthToken(ctx context.Context, r AuthTokenRecord) error
	// AuthTokensIssuedAgainst returns the auth tokens issued against the
	// presented token (iss, jti).
	AuthTokensIssuedAgainst(ctx context.Context, iss, jti string) ([]AuthTokenRecord, error)
	// Revoke records the revocation of (iss, jti) until exp; IsRevoked
	// reports it.
	Revoke(ctx context.Context, iss, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, iss, jti string) (bool, error)

	// CreatePending stores a new pending request (Version 1).
	CreatePending(ctx context.Context, p *Pending) error
	// Pending returns pending request id, or ErrNotFound.
	Pending(ctx context.Context, id string) (*Pending, error)
	// PendingByCode returns the pending request with the canonical
	// interaction code, or ErrNotFound.
	PendingByCode(ctx context.Context, code string) (*Pending, error)
	// UpdatePending replaces p if its Version matches (ErrConflict
	// otherwise) and increments it.
	UpdatePending(ctx context.Context, p *Pending) error
	// PendingForResourceToken returns the open pending requests started
	// for the resource token (iss, jti).
	PendingForResourceToken(ctx context.Context, iss, jti string) ([]*Pending, error)
}

// MemoryStore is an in-memory [Store] for tests and examples; state is
// lost on restart and not shared between instances.
type MemoryStore struct {
	mu      sync.Mutex
	auths   []AuthTokenRecord
	revoked map[[2]string]time.Time
	pending map[string][]byte
	codes   map[string]string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{revoked: map[[2]string]time.Time{}, pending: map[string][]byte{}, codes: map[string]string{}}
}

var _ Store = (*MemoryStore)(nil)

// RecordAuthToken implements Store.
func (m *MemoryStore) RecordAuthToken(_ context.Context, r AuthTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auths = append(m.auths, r)
	return nil
}

// AuthTokensIssuedAgainst implements Store.
func (m *MemoryStore) AuthTokensIssuedAgainst(_ context.Context, iss, jti string) ([]AuthTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AuthTokenRecord
	for _, r := range m.auths {
		if r.PresentedIssuer == iss && r.PresentedJTI == jti {
			out = append(out, r)
		}
	}
	return out, nil
}

// Revoke implements Store.
func (m *MemoryStore) Revoke(_ context.Context, iss, jti string, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[[2]string{iss, jti}] = exp
	return nil
}

// IsRevoked implements Store.
func (m *MemoryStore) IsRevoked(_ context.Context, iss, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[[2]string{iss, jti}]
	return ok, nil
}

// CreatePending implements Store.
func (m *MemoryStore) CreatePending(_ context.Context, p *Pending) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[p.ID]; ok {
		return ErrExists
	}
	p.Version = 1
	return m.put(p)
}

// Pending implements Store.
func (m *MemoryStore) Pending(_ context.Context, id string) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.get(id)
}

// PendingByCode implements Store.
func (m *MemoryStore) PendingByCode(_ context.Context, code string) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.codes[code]
	if !ok {
		return nil, ErrNotFound
	}
	return m.get(id)
}

// UpdatePending implements Store.
func (m *MemoryStore) UpdatePending(_ context.Context, p *Pending) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, err := m.get(p.ID)
	if err != nil {
		return err
	}
	if cur.Version != p.Version {
		return ErrConflict
	}
	p.Version++
	return m.put(p)
}

// PendingForResourceToken implements Store.
func (m *MemoryStore) PendingForResourceToken(_ context.Context, iss, jti string) ([]*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.pending))
	for id := range m.pending {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []*Pending
	for _, id := range ids {
		p, err := m.get(id)
		if err != nil {
			return nil, err
		}
		if p.Open() && p.ResourceTokenIssuer == iss && p.ResourceTokenJTI == jti {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *MemoryStore) put(p *Pending) error {
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

func (m *MemoryStore) get(id string) (*Pending, error) {
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
