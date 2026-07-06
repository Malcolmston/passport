// Package sessiontoken authenticates requests by reading an opaque session token
// from a named cookie and validating it with a user-supplied Verify function
// (typically a session-store lookup). It models the classic server-side session
// pattern: the cookie carries only a meaningless identifier, and the real
// session state lives on the server keyed by that identifier.
//
// Use this strategy when you keep sessions in a store (in-memory, Redis, a
// database, ...) and want passport to resolve the logged-in user from the
// session cookie on each request. It is the stateful complement to
// strategies/sessionjwt: because the token is opaque and validated against your
// store, you can revoke a session instantly (delete the row) and change its
// contents without re-issuing anything to the client — at the cost of a lookup on
// every request.
//
// On each request the strategy reads the cookie named Options.Cookie (default
// "session"); a missing or empty cookie is a 401 failure ("Missing session"). It
// then passes the cookie value to Options.Verify, which looks the token up in
// your store and returns the associated user. Returning the sentinel
// ErrInvalidToken (for an unknown or expired session) is treated as a 401 failure
// ("Invalid session"), as is returning a nil user with a nil error. Any other
// non-nil error is reported as an internal error, so a store outage is not
// mistaken for a bad session.
//
// The token is opaque to this strategy: it never parses or interprets the value,
// so you control its format, entropy and lifetime entirely in the store. Generate
// tokens with a cryptographically secure random source, set the cookie HttpOnly,
// Secure and SameSite, and expire sessions server-side to bound their lifetime.
//
// Parity note: this mirrors the session-cookie behavior of Passport.js's built-in
// session support, but factored as an explicit strategy with a pluggable Verify
// lookup rather than relying on a framework session middleware. Session creation
// and destruction (writing and clearing the cookie, populating the store) are the
// application's responsibility; this strategy handles the read/verify half.
package sessiontoken

import (
	"errors"
	"net/http"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a Verify func may return to signal
// an unknown or expired session (treated as an authentication failure).
var ErrInvalidToken = errors.New("invalid session token")

// VerifyFunc validates a session token, returning the authenticated user.
type VerifyFunc func(token string) (user any, err error)

// Options configures the sessiontoken Strategy.
type Options struct {
	// Cookie names the cookie carrying the session token. Defaults to "session".
	Cookie string
	// Verify validates the extracted token.
	Verify VerifyFunc
}

// Strategy authenticates requests bearing a session-token cookie.
type Strategy struct {
	cookie string
	verify VerifyFunc
}

// New creates a sessiontoken Strategy. opts.Cookie defaults to "session".
func New(opts Options) *Strategy {
	cookie := opts.Cookie
	if cookie == "" {
		cookie = "session"
	}
	return &Strategy{cookie: cookie, verify: opts.Verify}
}

// Name returns "session-token".
func (s *Strategy) Name() string { return "session-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	cookie, err := r.Cookie(s.cookie)
	if err != nil || cookie.Value == "" {
		c.Fail("Missing session", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(cookie.Value)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Invalid session", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Invalid session", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
