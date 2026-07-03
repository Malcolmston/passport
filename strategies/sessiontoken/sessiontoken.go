// Package sessiontoken authenticates requests by reading an opaque session
// token from a named cookie and validating it with a user-supplied Verify
// function (typically a session-store lookup).
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
