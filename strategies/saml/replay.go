package saml

import (
	"errors"
	"sync"
	"time"
)

// ErrReplay is returned when an assertion ID has already been consumed.
var ErrReplay = errors.New("saml: assertion has already been used (replay detected)")

// ReplayCache records the IDs of assertions that have already been accepted so
// that a captured SAMLResponse cannot be posted twice. Implementations must be
// safe for concurrent use.
//
// A single-process implementation is enough for a single-process service; a
// deployment behind a load balancer should back this with a shared store
// (Redis, memcached, a database table) so that a replay cannot simply be aimed
// at a different instance.
type ReplayCache interface {
	// Store records id and reports whether it was previously unseen. It
	// returns false when the ID has already been recorded and is still
	// within its validity window. expires is the instant after which the
	// entry may be forgotten, because an assertion past its NotOnOrAfter is
	// rejected on timing grounds anyway.
	Store(id string, expires time.Time) (fresh bool, err error)
}

// ErrReplayCacheFull is returned by MemoryReplayCache when it holds MaxEntries
// unexpired assertions. Rejecting is deliberate: silently forgetting entries
// under pressure would let an attacker flush the cache and then replay.
var ErrReplayCacheFull = errors.New("saml: replay cache is full")

// DefaultReplayCacheMaxEntries bounds the default in-memory replay cache.
const DefaultReplayCacheMaxEntries = 100_000

// MemoryReplayCache is the default ReplayCache: a concurrency-safe in-memory
// map that is bounded both by entry expiry and by MaxEntries. The zero value is
// ready to use.
type MemoryReplayCache struct {
	// MaxEntries caps how many unexpired assertion IDs are held. Zero
	// selects DefaultReplayCacheMaxEntries. An unbounded cache is itself a
	// denial-of-service vector, so there is no "no limit" setting.
	MaxEntries int
	// Clock supplies the current time; nil means time.Now.
	Clock func() time.Time

	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryReplayCache returns an empty MemoryReplayCache holding at most
// maxEntries unexpired IDs. A maxEntries of zero selects the default.
func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	return &MemoryReplayCache{MaxEntries: maxEntries}
}

func (c *MemoryReplayCache) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now()
}

// Store implements ReplayCache.
func (c *MemoryReplayCache) Store(id string, expires time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}
	now := c.now()
	if exp, ok := c.entries[id]; ok {
		if now.Before(exp) {
			return false, nil
		}
		// The old entry has lapsed; the ID is reusable in principle, but the
		// assertion carrying it will fail its own timing checks.
		delete(c.entries, id)
	}
	max := c.MaxEntries
	if max <= 0 {
		max = DefaultReplayCacheMaxEntries
	}
	if len(c.entries) >= max {
		c.evictExpiredLocked(now)
		if len(c.entries) >= max {
			return false, ErrReplayCacheFull
		}
	}
	c.entries[id] = expires
	return true, nil
}

// Len reports how many entries are currently held, expired ones included. It is
// intended for tests and metrics.
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *MemoryReplayCache) evictExpiredLocked(now time.Time) {
	for k, exp := range c.entries {
		if !now.Before(exp) {
			delete(c.entries, k)
		}
	}
}
