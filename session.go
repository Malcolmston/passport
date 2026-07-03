package passport

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
)

// DefaultCookieName is the cookie used to track the session id.
const DefaultCookieName = "passport.sid"

// Store persists session data keyed by an opaque session id. Implementations
// must be safe for concurrent use.
type Store interface {
	// Get returns the data for a session id and whether it exists.
	Get(id string) (map[string]any, bool)
	// Set stores data for a session id.
	Set(id string, data map[string]any)
	// Destroy removes a session.
	Destroy(id string)
}

// MemoryStore is an in-memory Store suitable for development and single-process
// deployments. For production across multiple processes, supply your own Store
// backed by Redis, a database, etc.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

// NewMemoryStore creates an empty in-memory session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string]map[string]any)}
}

// Get implements Store.
func (m *MemoryStore) Get(id string) (map[string]any, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[id]
	if !ok {
		return nil, false
	}
	// Return a copy so callers cannot mutate the store without Set.
	cp := make(map[string]any, len(d))
	for k, v := range d {
		cp[k] = v
	}
	return cp, true
}

// Set implements Store.
func (m *MemoryStore) Set(id string, data map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	m.data[id] = cp
}

// Destroy implements Store.
func (m *MemoryStore) Destroy(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
}

// sessionManager wires a Store to HTTP cookies.
type sessionManager struct {
	store      Store
	cookieName string
	secure     bool
	httpOnly   bool
	sameSite   http.SameSite
}

func newSessionManager(store Store) *sessionManager {
	return &sessionManager{
		store:      store,
		cookieName: DefaultCookieName,
		httpOnly:   true,
		sameSite:   http.SameSite(http.SameSiteLaxMode),
	}
}

// session represents the loaded session for one request. Changes are flushed to
// the store and cookie by save().
type session struct {
	mgr   *sessionManager
	id    string
	data  map[string]any
	dirty bool
	isNew bool
}

// load reads the session id from the request cookie, hydrating existing data or
// preparing a fresh session.
func (sm *sessionManager) load(r *http.Request) *session {
	s := &session{mgr: sm, data: map[string]any{}}
	if c, err := r.Cookie(sm.cookieName); err == nil && c.Value != "" {
		if data, ok := sm.store.Get(c.Value); ok {
			s.id = c.Value
			s.data = data
			return s
		}
	}
	s.isNew = true
	return s
}

// Get returns a session value.
func (s *session) Get(key string) (any, bool) {
	v, ok := s.data[key]
	return v, ok
}

// Set stores a session value and marks the session dirty.
func (s *session) Set(key string, value any) {
	s.data[key] = value
	s.dirty = true
}

// Delete removes a session value.
func (s *session) Delete(key string) {
	delete(s.data, key)
	s.dirty = true
}

// regenerate assigns a fresh session id, defeating session-fixation attacks on
// privilege changes such as login.
func (s *session) regenerate() error {
	if s.id != "" {
		s.mgr.store.Destroy(s.id)
	}
	id, err := newSessionID()
	if err != nil {
		return err
	}
	s.id = id
	s.dirty = true
	return nil
}

// save persists the session to the store and (for new sessions) writes the
// cookie. It is a no-op when nothing changed.
func (s *session) save(w http.ResponseWriter) error {
	if !s.dirty {
		return nil
	}
	if s.id == "" {
		id, err := newSessionID()
		if err != nil {
			return err
		}
		s.id = id
	}
	s.mgr.store.Set(s.id, s.data)
	http.SetCookie(w, &http.Cookie{
		Name:     s.mgr.cookieName,
		Value:    s.id,
		Path:     "/",
		HttpOnly: s.mgr.httpOnly,
		Secure:   s.mgr.secure,
		SameSite: s.mgr.sameSite,
	})
	s.dirty = false
	return nil
}

// destroy removes the session and clears the client cookie.
func (s *session) destroy(w http.ResponseWriter) {
	if s.id != "" {
		s.mgr.store.Destroy(s.id)
	}
	s.data = map[string]any{}
	http.SetCookie(w, &http.Cookie{
		Name:     s.mgr.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: s.mgr.httpOnly,
		Secure:   s.mgr.secure,
		SameSite: s.mgr.sameSite,
	})
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
