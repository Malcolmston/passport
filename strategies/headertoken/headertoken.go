// Package headertoken authenticates requests by reading an opaque token from an
// arbitrary, caller-specified request header and validating it with a
// user-supplied Verify function. It ports the generic "custom header token"
// idea found in the Passport.js ecosystem — strategies such as
// passport-http-header-strategy and passport-headerapikey — using only the Go
// standard library.
//
// Use this strategy when clients authenticate by presenting a simple bearer
// credential (an API key, a session token, a personal access token) in a
// dedicated HTTP header rather than in the Authorization header or a form body.
// It is the least opinionated of the token strategies: it does not parse, sign,
// or interpret the token in any way, leaving all validation semantics to your
// Verify function. This makes it a good fit for internal services, machine-to-
// machine APIs, and webhook receivers where you control both ends and want to
// map a raw string to an application user with minimal ceremony.
//
// The flow is deliberately small. On each request the Strategy reads the header
// named by Options.Header (defaulting to "X-Auth-Token"); a missing or empty
// header fails the request with 401. The extracted token is passed to
// Options.Verify, whose (user, err) result drives the outcome: a non-nil user
// authenticates the request and becomes passport.User(r), while a nil user or a
// returned error rejects it.
//
// The Verify contract distinguishes expected authentication failures from
// unexpected faults. Returning the ErrInvalidToken sentinel (or any error that
// errors.Is-matches it), or returning a nil user with a nil error, produces a
// 401 Unauthorized. Returning any other error is treated as a server-side
// problem and is surfaced through the passport error path rather than as a
// clean authentication failure, so reserve non-sentinel errors for genuine
// infrastructure issues such as a database lookup failing.
//
// Parity with Passport.js: like its Node counterparts, the strategy is a thin
// adapter that delegates credential validation to an application-supplied
// callback and reports success, failure, or error back to the framework. The
// Verify(token) -> (user, err) shape mirrors the Node verify(token, done)
// convention, ErrInvalidToken plays the role of calling done(null, false), and
// the configurable header name matches the Node option for choosing which
// header carries the token. The Strategy's registered name is "header-token".
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
