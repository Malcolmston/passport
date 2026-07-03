// Package custom provides a generic adapter for defining ad-hoc authentication
// strategies inline, without writing a new type. Given a name and a function
// that inspects the request, New returns a passport.Strategy that:
//
//   - reports Error when the function returns a non-nil error,
//   - reports Success when it returns a non-nil user,
//   - reports Fail when it returns a nil user and nil error.
//
// It is handy for one-off checks (a header, an IP allowlist, a signed query
// parameter) that do not warrant a dedicated package.
package custom

import (
	"net/http"

	"github.com/malcolmston/passport"
)

// AuthFunc inspects the request and returns the authenticated user, or nil to
// reject, or an error for an internal failure.
type AuthFunc func(r *http.Request) (user any, err error)

// Strategy adapts an AuthFunc to the passport.Strategy interface.
type Strategy struct {
	name string
	fn   AuthFunc
}

// New creates a Strategy registered under name that authenticates with fn.
func New(name string, fn AuthFunc) *Strategy {
	return &Strategy{name: name, fn: fn}
}

// Name returns the strategy name.
func (s *Strategy) Name() string { return s.name }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	if s.fn == nil {
		c.Pass()
		return
	}
	user, err := s.fn(r)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
