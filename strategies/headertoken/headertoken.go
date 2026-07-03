// Package headertoken authenticates requests by reading a token from an
// arbitrary, caller-specified request header and validating it with a
// user-supplied Verify function.
package headertoken

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

// Options configures the headertoken Strategy.
type Options struct {
	// Header names the request header carrying the token. Defaults to
	// "X-Auth-Token".
	Header string
	// Verify validates the extracted token.
	Verify VerifyFunc
}

// Strategy authenticates requests bearing a token in a custom header.
type Strategy struct {
	header string
	verify VerifyFunc
}

// New creates a headertoken Strategy. opts.Header defaults to "X-Auth-Token".
func New(opts Options) *Strategy {
	header := opts.Header
	if header == "" {
		header = "X-Auth-Token"
	}
	return &Strategy{header: header, verify: opts.Verify}
}

// Name returns "header-token".
func (s *Strategy) Name() string { return "header-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := r.Header.Get(s.header)
	if token == "" {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(token)
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
