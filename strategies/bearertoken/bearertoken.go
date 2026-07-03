// Package bearertoken implements opaque bearer-token authentication via token
// introspection. The token is read from the "Authorization: Bearer <token>"
// header and handed to a user-supplied Verify function that introspects it
// (e.g. against a token store or introspection endpoint).
package bearertoken

import (
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a Verify func may return to signal
// an invalid or expired token (treated as an authentication failure).
var ErrInvalidToken = errors.New("invalid token")

// VerifyFunc introspects an opaque token, returning the authenticated user on
// success.
type VerifyFunc func(token string) (user any, err error)

// Strategy authenticates requests bearing an opaque access token.
type Strategy struct {
	verify VerifyFunc
}

// New creates a bearertoken Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{verify: verify}
}

// Name returns "bearer-token".
func (s *Strategy) Name() string { return "bearer-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
