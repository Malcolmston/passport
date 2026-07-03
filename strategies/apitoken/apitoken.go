// Package apitoken authenticates requests bearing an opaque API token. The
// token is read from the Authorization header ("Bearer <t>" or "Token <t>") or
// from an "X-API-Token" header, and validated against a caller-supplied set.
//
// Validation is constant-time: the static-token convenience path compares with
// crypto/subtle.ConstantTimeCompare to avoid leaking the token through response
// timing, and the ConstantTimeEqual helper is exported for Lookup
// implementations that compare secrets themselves.
//
// This package is intentionally distinct from strategies/apikey: it takes a
// bearer-style token (not an X-API-Key header) and its store is a Lookup
// function returning the user directly.
package apitoken

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// LookupFunc resolves a presented token to a user. ok is false for unknown or
// revoked tokens.
type LookupFunc func(token string) (user any, ok bool)

// Options configures the strategy. Set Lookup for a dynamic token store, or
// Token+User for a single static token compared in constant time. If both are
// set, Lookup takes precedence.
type Options struct {
	// Lookup resolves a presented token to a user.
	Lookup LookupFunc
	// Token is a single valid token (constant-time compared) when Lookup is nil.
	Token string
	// User is the user yielded when a request presents Token.
	User any
	// Header is an additional header to consult. Defaults to "X-API-Token".
	Header string
}

// Strategy authenticates requests presenting an API token.
type Strategy struct {
	opts   Options
	header string
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	header := opts.Header
	if header == "" {
		header = "X-API-Token"
	}
	return &Strategy{opts: opts, header: header}
}

// Name returns "api-token".
func (s *Strategy) Name() string { return "api-token" }

// ConstantTimeEqual reports whether a and b are equal using a constant-time
// comparison, safe against timing attacks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// extractToken pulls the token from the Authorization header (Bearer/Token
// scheme) or the configured header.
func (s *Strategy) extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			return strings.TrimSpace(h[7:])
		}
		if len(h) > 6 && strings.EqualFold(h[:6], "token ") {
			return strings.TrimSpace(h[6:])
		}
	}
	return strings.TrimSpace(r.Header.Get(s.header))
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := s.extractToken(r)
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}

	if s.opts.Lookup != nil {
		if user, ok := s.opts.Lookup(token); ok && user != nil {
			c.Success(user)
			return
		}
		c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}

	if s.opts.Token != "" && ConstantTimeEqual(token, s.opts.Token) {
		c.Success(s.opts.User)
		return
	}
	c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
}
