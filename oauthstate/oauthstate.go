// Package oauthstate provides CSRF "state" handling for OAuth 2.0
// authorization-code flows in the passport port. The strategies/oauth2 base
// passes the state parameter through opaquely but neither generates nor
// validates it; this package fills that gap, mirroring the state-store concept
// from Node's passport-oauth2.
//
// Two independent styles are offered. A stateful MemoryStore issues a random
// nonce, remembers it (optionally with an application-defined payload), and
// consumes it exactly once on the callback — the classic server-side approach.
// A stateless HMACStore instead signs a payload with a secret key so the state
// is self-verifying and needs no server storage, at the cost of the state
// string being larger and, if a payload is attached, visible to the user agent.
//
// Both styles satisfy the Store interface, so calling code can swap one for the
// other. All signing and comparison use the standard library and constant-time
// checks; only nonce generation is non-deterministic.
package oauthstate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Errors returned by the stores.
var (
	// ErrUnknownState is returned when a state value was never issued, has
	// already been consumed, or has expired.
	ErrUnknownState = errors.New("oauthstate: unknown or expired state")

	// ErrBadSignature is returned by HMACStore.Verify when a state's
	// signature does not match, indicating tampering or the wrong key.
	ErrBadSignature = errors.New("oauthstate: signature mismatch")
)

// Store issues opaque state values and verifies them on the OAuth callback.
// Verify returns the payload that was associated with the state at Issue time
// (empty when none was supplied).
type Store interface {
	// Issue returns a new state string carrying the given payload.
	Issue(payload string) (string, error)
	// Verify checks a returned state and yields its original payload.
	Verify(state string) (payload string, err error)
}

// GenerateNonce returns a URL-safe random string built from 16 bytes of
// entropy, suitable as an OAuth state value or general CSRF token.
func GenerateNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauthstate: reading random source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

type stateEntry struct {
	payload string
	expires time.Time
}

// MemoryStore is a single-request, server-side Store. Each issued state is
// remembered until it is consumed by Verify or its TTL elapses. It is safe for
// concurrent use.
type MemoryStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]stateEntry
}

// NewMemoryStore returns a MemoryStore whose issued states expire after ttl. A
// non-positive ttl disables expiry.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	return &MemoryStore{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]stateEntry),
	}
}

// Issue generates a nonce, stores payload against it, and returns the nonce.
func (s *MemoryStore) Issue(payload string) (string, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	var exp time.Time
	if s.ttl > 0 {
		exp = s.now().Add(s.ttl)
	}
	s.mu.Lock()
	s.entries[nonce] = stateEntry{payload: payload, expires: exp}
	s.mu.Unlock()
	return nonce, nil
}

// Verify consumes state, returning the payload that was stored with it. It
// returns ErrUnknownState if the state is absent, already consumed, or expired.
// A state is removed whether or not it had expired.
func (s *MemoryStore) Verify(state string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return "", ErrUnknownState
	}
	delete(s.entries, state)
	if !e.expires.IsZero() && s.now().After(e.expires) {
		return "", ErrUnknownState
	}
	return e.payload, nil
}

// Len reports how many issued-but-unconsumed states the store currently holds,
// including any that have expired but not yet been swept.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// HMACStore is a stateless Store: the state string is the base64url of a random
// nonce and optional payload, authenticated by an HMAC-SHA256 tag over both. No
// server-side storage is required, so it works across restarts and horizontally
// scaled instances that share the secret key.
type HMACStore struct {
	key []byte
	now func() time.Time
	ttl time.Duration
}

// NewHMACStore returns an HMACStore that signs with key. If ttl is positive,
// Verify rejects states older than ttl. The key should be at least 32 bytes of
// unpredictable data.
func NewHMACStore(key []byte, ttl time.Duration) *HMACStore {
	dup := make([]byte, len(key))
	copy(dup, key)
	return &HMACStore{key: dup, now: time.Now, ttl: ttl}
}

func (s *HMACStore) sign(msg string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Issue returns a signed state of the form
// base64url(nonce)."."base64url(unixSeconds)."."base64url(payload)."."tag.
func (s *HMACStore) Issue(payload string) (string, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	ts := fmt.Sprintf("%d", s.now().Unix())
	body := strings.Join([]string{
		nonce,
		base64.RawURLEncoding.EncodeToString([]byte(ts)),
		base64.RawURLEncoding.EncodeToString([]byte(payload)),
	}, ".")
	return body + "." + s.sign(body), nil
}

// Verify recomputes the signature over a returned state and, on a match,
// returns the embedded payload. It returns ErrBadSignature for a tampered or
// wrongly keyed state and ErrUnknownState for a malformed or expired one.
func (s *HMACStore) Verify(state string) (string, error) {
	i := strings.LastIndex(state, ".")
	if i < 0 {
		return "", ErrUnknownState
	}
	body, tag := state[:i], state[i+1:]
	expected := s.sign(body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(tag)) != 1 {
		return "", ErrBadSignature
	}
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return "", ErrUnknownState
	}
	tsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrUnknownState
	}
	if s.ttl > 0 {
		var unix int64
		if _, err := fmt.Sscanf(string(tsRaw), "%d", &unix); err != nil {
			return "", ErrUnknownState
		}
		if s.now().Sub(time.Unix(unix, 0)) > s.ttl {
			return "", ErrUnknownState
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrUnknownState
	}
	return string(payload), nil
}
