// Package custom provides a generic adapter for defining ad-hoc authentication
// strategies inline, without writing a new type. It is the Go analogue of
// Passport.js's passport-custom: instead of shipping a strategy package, you pass
// a function that inspects the raw *http.Request and returns the authenticated
// user. New wraps that function in a value that satisfies passport.Strategy.
//
// Use it as an escape hatch whenever no built-in strategy fits: a one-off header
// or query-parameter check, an IP allowlist, a signed-URL verifier, an HMAC
// webhook signature, a bridge to a bespoke or legacy auth service, or a quick
// stub in tests. Anything you can decide from the request alone can become a
// strategy in a few lines, and you register it under a name of your choosing so
// it can sit alongside the other strategies you pass to passport.
//
// Given a name and an AuthFunc, New returns a passport.Strategy that maps the
// function's result onto passport's outcomes:
//
//   - it reports Error when the function returns a non-nil error,
//   - it reports Success when the function returns a non-nil user,
//   - it reports Fail (HTTP 401) when the function returns a nil user and nil error.
//
// The AuthFunc contract is therefore the whole API: return a non-nil user to
// authenticate (that value becomes passport.User), return a nil user with a nil
// error to reject the request as an authentication failure, or return a non-nil
// error to signal an internal problem that should surface as a server error
// rather than a normal failure. As a safety net, if a Strategy is constructed
// with a nil AuthFunc, Authenticate calls Context.Pass so the request is neither
// authenticated nor failed.
//
// Parity note: like passport-custom this package supplies no verification logic
// of its own -- it is purely the adapter, and all behavior lives in the function
// you provide. There is no session or redirect handling here; combine it with the
// passport.Options you would use for any other strategy (for example
// Session: false for stateless API checks).
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
