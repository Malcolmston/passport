// Package anonymous implements a pass-through authentication strategy for the
// passport port, a Go port of passport-anonymous. It never authenticates and
// never fails: it simply declines to handle the request (it "passes"), allowing
// the request to proceed with no authenticated user attached.
//
// Its purpose is to make authentication optional on a route. Passport's
// Authenticate normally responds with 401 when a strategy fails; by falling back
// to the anonymous strategy you instead let unauthenticated requests through, so
// a single handler can serve both signed-in users and guests. Typical uses are
// public pages that show extra content when logged in, or APIs that personalize a
// response only when a credential happens to be present.
//
// Mechanically, Authenticate calls the context's Pass method, which signals "no
// opinion" rather than success or failure. The strategy inspects nothing about
// the request and stores no user, so after it runs passport.User returns whatever
// a prior strategy or the session established — often nil.
//
// Because it always passes, anonymous should be combined with a real strategy (or
// placed after one in the chain) rather than used alone to protect anything; on
// its own it grants everyone access. Handlers behind it must check passport.User
// or passport.IsAuthenticated and degrade gracefully when no user is present.
//
// Parity: this mirrors passport-anonymous, whose entire job is to "pass" so that
// authentication can be treated as optional. It carries no options and has no
// provider, endpoints or verify callback — the surrounding passport.Passport and
// the other strategies in the chain determine who, if anyone, is logged in.
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
