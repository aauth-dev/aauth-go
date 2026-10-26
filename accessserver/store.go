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
	// ErrCodeInUse means another stored pending request has the same
	// canonical interaction code; the server draws a new one.
	ErrCodeInUse = errors.New("accessserver: interaction code in use")
	// ErrRevoked means the token an auth token was issued against has
	// been revoked, so the auth token was not recorded.
	ErrRevoked = errors.New("accessserver: presented token revoked")
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
	// RecordAuthToken records an issued auth token, unless the presented
	// token (r.PresentedIssuer, r.PresentedJTI) has been revoked: then it
	// records nothing and returns ErrRevoked. The check and the insert
	// MUST be atomic with respect to Revoke, so that a revocation stored
	// before the insert is seen here and one stored after it finds r
	// through AuthTokensIssuedAgainst. Otherwise an issuance racing a
	// revocation escapes the cascade (§11.12.4).
	RecordAuthToken(ctx context.Context, r AuthTokenRecord) error
	// AuthTokensIssuedAgainst returns the auth tokens issued against the
	// presented token (iss, jti).
	AuthTokensIssuedAgainst(ctx context.Context, iss, jti string) ([]AuthTokenRecord, error)
	// Revoke records the revocation of (iss, jti) until exp; IsRevoked
	// reports it. CountRevocations returns how many revocations of tokens
	// issued by iss are recorded (Config.MaxRevocationsPerIssuer).
	Revoke(ctx context.Context, iss, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, iss, jti string) (bool, error)
	CountRevocations(ctx context.Context, iss string) (int, error)

	// CreatePending stores a new pending request (Version 1).
	// CreatePending and UpdatePending MUST fail with ErrCodeInUse, storing
	// nothing, when another stored request has the same non-empty
	// CodeCanonical, so PendingByCode names one request.
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
	// CountOpenPending returns how many open pending requests the PS ps
	// has (Config.MaxPendingPerPS).
	CountOpenPending(ctx context.Context, ps string) (int, error)

	// Prune discards the records whose lifetime ended before cutoff:
	// pending requests whose ExpiresAt, and revocations and auth token
	// records whose exp, is before it. The server calls it with the
	// current time less clock skew every Config.PruneInterval, and
	// [Server.Prune] on demand.
	Prune(ctx context.Context, cutoff time.Time) error
}

// MemoryStore is an in-memory [Store] for tests and examples; state is
// lost on restart and not shared between instances. Expired records are
// discarded when Prune is called.
type MemoryStore struct {
	mu       sync.Mutex
	auths    []AuthTokenRecord
	revoked  map[[2]string]time.Time
	revCount map[string]int
	pending  map[string][]byte
	meta     map[string]pendingMeta
	codes    map[string]string
}

// pendingMeta indexes a stored pending request, so lookups do not decode
// every record.
type pendingMeta struct {
	ps           string
	open         bool
	rtIss, rtJTI string
	code         string
	expires      time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{revoked: map[[2]string]time.Time{}, revCount: map[string]int{}, pending: map[string][]byte{},
		meta: map[string]pendingMeta{}, codes: map[string]string{}}
}

var _ Store = (*MemoryStore)(nil)

// RecordAuthToken implements Store.
func (m *MemoryStore) RecordAuthToken(_ context.Context, r AuthTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.revoked[[2]string{r.PresentedIssuer, r.PresentedJTI}]; ok {
		return ErrRevoked
	}
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
	k := [2]string{iss, jti}
	if prev, ok := m.revoked[k]; ok {
		if exp.Before(prev) {
			exp = prev // never shorten a revocation
		}
	} else {
		m.revCount[iss]++
	}
	m.revoked[k] = exp
	return nil
}

// CountRevocations implements Store.
func (m *MemoryStore) CountRevocations(_ context.Context, iss string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revCount[iss], nil
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
	if m.codeTaken(p) {
		return ErrCodeInUse
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
	if m.codeTaken(p) {
		return ErrCodeInUse
	}
	p.Version++
	return m.put(p)
}

// PendingForResourceToken implements Store.
func (m *MemoryStore) PendingForResourceToken(_ context.Context, iss, jti string) ([]*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, mt := range m.meta {
		if mt.open && mt.rtIss == iss && mt.rtJTI == jti {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	out := make([]*Pending, 0, len(ids))
	for _, id := range ids {
		p, err := m.get(id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// CountOpenPending implements Store.
func (m *MemoryStore) CountOpenPending(_ context.Context, ps string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, mt := range m.meta {
		if mt.open && mt.ps == ps {
			n++
		}
	}
	return n, nil
}

// Prune implements Store.
func (m *MemoryStore) Prune(_ context.Context, cutoff time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, mt := range m.meta {
		if mt.expires.Before(cutoff) {
			delete(m.pending, id)
			delete(m.meta, id)
			if mt.code != "" && m.codes[mt.code] == id {
				delete(m.codes, mt.code)
			}
		}
	}
	for k, exp := range m.revoked {
		if exp.Before(cutoff) {
			delete(m.revoked, k)
			if m.revCount[k[0]]--; m.revCount[k[0]] <= 0 {
				delete(m.revCount, k[0])
			}
		}
	}
	m.auths = slices.DeleteFunc(m.auths, func(r AuthTokenRecord) bool { return r.Exp.Before(cutoff) })
	return nil
}

// codeTaken reports whether another request holds p's code; m.mu is held.
func (m *MemoryStore) codeTaken(p *Pending) bool {
	id, ok := m.codes[p.CodeCanonical]
	return ok && p.CodeCanonical != "" && id != p.ID
}

func (m *MemoryStore) put(p *Pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if prev := m.meta[p.ID].code; prev != "" && prev != p.CodeCanonical && m.codes[prev] == p.ID {
		delete(m.codes, prev) // a re-evaluation drew a new code
	}
	m.pending[p.ID] = b
	m.meta[p.ID] = pendingMeta{ps: p.PS, open: p.Open(), rtIss: p.ResourceTokenIssuer, rtJTI: p.ResourceTokenJTI,
		code: p.CodeCanonical, expires: p.ExpiresAt}
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
