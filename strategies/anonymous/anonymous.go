// Package anonymous implements a pass-through strategy, a Go port of
// passport-anonymous. It never fails: it simply declines, allowing a request to
// proceed unauthenticated. Combine it with another strategy to make
// authentication optional on a route.
package anonymous

import (
	"net/http"

	"github.com/malcolmston/passport"
)

// Strategy always passes, leaving the request unauthenticated.
type Strategy struct{}

// New creates an anonymous Strategy.
func New() *Strategy { return &Strategy{} }

// Name returns "anonymous".
func (s *Strategy) Name() string { return "anonymous" }

// Authenticate implements passport.Strategy by declining to handle the request.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	c.Pass()
}
