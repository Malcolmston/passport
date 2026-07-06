// Package apitoken implements opaque API-token authentication for the passport
// port. It is a bearer-style companion to strategies/apikey and covers similar
// ground to token variants of passport-http-bearer: a client presents a token
// and a caller-supplied store resolves it to a user, but here the token travels
// in the Authorization header rather than an X-API-Key header.
//
// Use this strategy for stateless service and programmatic access when your
// tokens are presented the way OAuth bearer tokens are — "Authorization: Bearer
// <token>" — but are opaque secrets you issue and validate yourself rather than
// signed JWTs. Like the other token strategies it establishes no session and is
// typically mounted with passport.Options{Session: false}.
//
// The token is extracted from the Authorization header using either the
// "Bearer " or "Token " scheme and, if neither is present, from a configurable
// header that defaults to "X-API-Token". A request carrying no token fails with a
// 401 "Bearer" challenge before any lookup runs.
//
// Validation supports two modes. Set Options.Lookup for a dynamic store: it
// returns (user, ok), and ok=false (or a nil user) rejects the token. Or set
// Options.Token together with Options.User for a single static token, which is
// compared with crypto/subtle.ConstantTimeCompare so the check does not leak the
// secret through response timing; the exported ConstantTimeEqual helper offers
// the same guarantee to Lookup implementations that compare secrets themselves.
// If both are configured, Lookup takes precedence.
//
// Parity: the mechanism follows the bearer-token convention of passport-http-
// bearer but is intentionally storage-first (a Lookup returning the user
// directly, or a constant-time static token) rather than a general verify
// callback, and it is deliberately distinct from strategies/apikey, which reads
// an X-API-Key header instead of an Authorization scheme. Token issuance, expiry
// and revocation live in the caller's Lookup.
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
