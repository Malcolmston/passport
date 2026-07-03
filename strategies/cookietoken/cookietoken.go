// Package cookietoken authenticates requests by reading a token from a named
// cookie and validating it with a user-supplied Verify function.
package cookietoken

import (
	"errors"
	"net/http"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a Verify func may return to signal
// an invalid token (treated as an authentication failure).
var ErrInvalidToken = errors.New("invalid token")

// VerifyFunc validates a token, returning the authenticated user.
type VerifyFunc func(token string) (user any, err error)

// Options configures the cookietoken Strategy.
type Options struct {
	// Cookie names the cookie carrying the token. Defaults to "token".
	Cookie string
	// Verify validates the extracted token.
	Verify VerifyFunc
}

// Strategy authenticates requests bearing a token in a cookie.
type Strategy struct {
	cookie string
	verify VerifyFunc
}

// New creates a cookietoken Strategy. opts.Cookie defaults to "token".
func New(opts Options) *Strategy {
	cookie := opts.Cookie
	if cookie == "" {
		cookie = "token"
	}
	return &Strategy{cookie: cookie, verify: opts.Verify}
}

// Name returns "cookie-token".
func (s *Strategy) Name() string { return "cookie-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	cookie, err := r.Cookie(s.cookie)
	if err != nil || cookie.Value == "" {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(cookie.Value)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Invalid token", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Invalid token", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
