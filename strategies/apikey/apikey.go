// Package apikey implements shared-secret API-key authentication for the
// passport port. It is the Go analogue of the community passport-headerapikey
// and passport-localapikey strategies for Passport.js: instead of a username and
// password, a caller presents a single opaque key that identifies a client or
// service, and a user-supplied Verify function resolves that key to an
// application user.
//
// Reach for this strategy for machine-to-machine and simple programmatic access
// where issuing full OAuth credentials is overkill: internal service calls,
// webhooks, cron jobs, or a developer API guarded by keys minted in a dashboard.
// It is stateless, so it pairs naturally with passport.Options{Session: false}
// and needs no cookies or redirects.
//
// On each request the key is read from a configurable header (defaulting to
// "X-API-Key") and, when Options.Query is set, falls back to that query
// parameter. If no key is present the request fails with 401 before Verify is
// called; when a key is found it is passed to Verify, which returns the
// authenticated user on success.
//
// The Verify contract distinguishes three outcomes: returning a non-nil user
// authenticates the request; returning (nil, nil) or (nil, ErrInvalidKey)
// rejects it as an authentication failure (401 "Invalid API key"); and returning
// (nil, err) for any other error is treated as an internal error and surfaced via
// the context's Error path. Verify should compare keys carefully — prefer a
// constant-time comparison or a hashed lookup — since a naive string compare can
// leak key material through timing.
//
// Parity: this mirrors the header/param key extraction of the Node strategies
// while leaving key storage, hashing and rotation entirely to Verify. It does
// not itself hash or persist keys, and unlike the bundled strategies/apitoken
// package it reads an X-API-Key-style header rather than a "Bearer"/"Token"
// Authorization scheme.
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
