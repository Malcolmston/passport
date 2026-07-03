// Package querytoken authenticates requests by reading a token from a query
// parameter (default "token") and validating it with a user-supplied Verify
// function.
package querytoken

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

// Options configures the querytoken Strategy.
type Options struct {
	// Param names the query parameter carrying the token. Defaults to "token".
	Param string
	// Verify validates the extracted token.
	Verify VerifyFunc
}

// Strategy authenticates requests bearing a token in the query string.
type Strategy struct {
	param  string
	verify VerifyFunc
}

// New creates a querytoken Strategy. opts.Param defaults to "token".
func New(opts Options) *Strategy {
	param := opts.Param
	if param == "" {
		param = "token"
	}
	return &Strategy{param: param, verify: opts.Verify}
}

// Name returns "query-token".
func (s *Strategy) Name() string { return "query-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := r.URL.Query().Get(s.param)
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
