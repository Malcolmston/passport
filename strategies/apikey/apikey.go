// Package apikey implements API-key authentication. The key is read from a
// configurable request header (default "X-API-Key") or, optionally, from a
// query parameter, and validated by a user-supplied Verify function.
package apikey

import (
	"errors"
	"net/http"

	"github.com/malcolmston/passport"
)

// ErrInvalidKey is a convenience sentinel a Verify func may return to signal an
// unknown or revoked key (treated as an authentication failure, not an error).
var ErrInvalidKey = errors.New("invalid api key")

// VerifyFunc validates an API key, returning the authenticated user on success.
// Return (nil, nil) or (nil, ErrInvalidKey) to reject the key, and (nil, err)
// for an internal error.
type VerifyFunc func(key string) (user any, err error)

// Options configures the apikey Strategy.
type Options struct {
	// Header is the request header carrying the key. Defaults to "X-API-Key".
	Header string
	// Query, when non-empty, is a query parameter also consulted for the key.
	Query string
	// Verify validates the extracted key.
	Verify VerifyFunc
}

// Strategy authenticates requests presenting a shared API key.
type Strategy struct {
	header string
	query  string
	verify VerifyFunc
}

// New creates an apikey Strategy from the given options. If opts.Header is
// empty it defaults to "X-API-Key".
func New(opts Options) *Strategy {
	header := opts.Header
	if header == "" {
		header = "X-API-Key"
	}
	return &Strategy{header: header, query: opts.Query, verify: opts.Verify}
}

// Name returns "apikey".
func (s *Strategy) Name() string { return "apikey" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	key := r.Header.Get(s.header)
	if key == "" && s.query != "" {
		key = r.URL.Query().Get(s.query)
	}
	if key == "" {
		c.Fail("Missing API key", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(key)
	if err != nil {
		if errors.Is(err, ErrInvalidKey) {
			c.Fail("Invalid API key", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Invalid API key", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
