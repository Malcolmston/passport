// Package bearer implements HTTP Bearer token authentication (RFC 6750), a Go
// port of passport-http-bearer. The token is taken from the Authorization
// header ("Bearer <token>"), the access_token form field, or the access_token
// query parameter, and validated by a user-supplied VerifyFunc.
package bearer

import (
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a VerifyFunc may return to signal
// an invalid token (treated as an authentication failure, not an error).
var ErrInvalidToken = errors.New("invalid token")

// VerifyFunc validates a bearer token, returning the authenticated user on
// success. Return (nil, nil) or (nil, ErrInvalidToken) to reject the token, and
// (nil, err) for an internal error.
type VerifyFunc func(token string) (user any, err error)

// Strategy authenticates requests bearing an opaque access token.
type Strategy struct {
	// Realm is reported in the WWW-Authenticate challenge on failure.
	Realm string

	verify VerifyFunc
}

// New creates a bearer Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{Realm: "Users", verify: verify}
}

// Name returns "bearer".
func (s *Strategy) Name() string { return "bearer" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		c.Fail("Bearer realm=\""+s.Realm+"\"", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Bearer realm=\""+s.Realm+"\", error=\"invalid_token\"", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Bearer realm=\""+s.Realm+"\", error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			return strings.TrimSpace(h[7:])
		}
	}
	if t := r.URL.Query().Get("access_token"); t != "" {
		return t
	}
	if r.Method != http.MethodGet {
		if err := r.ParseForm(); err == nil {
			if t := r.PostFormValue("access_token"); t != "" {
				return t
			}
		}
	}
	return ""
}
