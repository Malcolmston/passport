// Package querytoken authenticates requests by reading a token from a URL query
// parameter (default "token") and validating it with a user-supplied Verify
// function. It is the query-string analogue of the header- and cookie-based
// token strategies, filling the same niche as passport-http-bearer configured to
// read the token from the query string in the Passport.js ecosystem.
//
// Use this strategy for the cases where a credential must ride in the URL rather
// than a header: signed download or unsubscribe links, email confirmation links,
// webhooks that only support query parameters, WebSocket handshakes, or
// third-party callbacks that cannot set an Authorization header. For ordinary
// API calls prefer a header-based bearer token, because query strings are more
// likely to be logged and leaked.
//
// On each request the strategy reads the query parameter named Options.Param
// (default "token"); a missing or empty value is a 401 failure ("Missing
// token"). It then passes the raw token to Options.Verify, which validates it and
// returns the authenticated user. Returning the sentinel ErrInvalidToken is
// treated as a 401 failure ("Invalid token"), as is returning a nil user with a
// nil error; any other non-nil error is reported as an internal error rather than
// a failure. On success the returned user becomes the authenticated user.
//
// Because the token appears in the URL, treat it as sensitive: URLs are recorded
// in browser history, proxy and server access logs, and Referer headers. Prefer
// single-use, short-lived, high-entropy tokens (for example an HMAC- or
// JWT-backed value your Verify function checks), always serve over TLS, and where
// possible rotate or expire the token immediately after use.
//
// Parity note: this is a small, focused strategy specific to the Go port. It only
// reads the token and delegates all validation to Verify, so token format,
// expiry and revocation are entirely under your control.
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
