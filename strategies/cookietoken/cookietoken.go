// Package cookietoken authenticates requests by reading an opaque token from a
// named HTTP cookie and validating it with a user-supplied VerifyFunc. It is a
// token-extraction strategy rather than a redirect or credential-prompt flow:
// the browser is expected to already hold a token (issued by your login
// endpoint) in a cookie, and this strategy turns that token into an
// authenticated user on each request.
//
// Reach for it when a token lives in a cookie rather than in an Authorization
// header -- for example a same-site web app that stores a session or API token
// client-side, or a setup where a reverse proxy or login service drops a signed
// token cookie that your backend must validate. It is the cookie-based counterpart
// to a bearer-token strategy.
//
// Configuration is through Options. Options.Cookie names the cookie to read and
// defaults to "token" when empty; Options.Verify is the validation function.
// On each request the strategy reads that cookie: if it is missing or empty, the
// request fails with "Missing token" and HTTP 401 without ever calling Verify.
//
// When a token is present it is passed to your VerifyFunc, whose contract decides
// the outcome. Returning a non-nil user authenticates the request and that value
// becomes passport.User. Returning a nil user (with a nil error), or the
// ErrInvalidToken sentinel, rejects the request with "Invalid token" and HTTP
// 401; any other non-nil error is treated as an internal error and reported via
// Context.Error. The strategy itself does not interpret the token -- signing,
// expiry, and revocation are entirely up to your Verify function.
//
// Security and parity notes: this package only reads and validates the cookie; it
// does not set it, so issue the cookie from your login handler with the flags your
// deployment needs (Secure, HttpOnly, SameSite). Because a cookie is sent
// automatically by the browser, protect state-changing endpoints against CSRF.
// The strategy registers under the name "cookie-token".
package cookietoken

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

// Options configures the cookietoken Strategy.
type Options struct {
	// Cookie names the cookie carrying the token. Defaults to "token".
	Cookie string
	// Verify validates the extracted token.
	Verify VerifyFunc
}

// Strategy authenticates requests bearing a token in a cookie.
type Strategy struct {
	cookie string
	verify VerifyFunc
}

// New creates a cookietoken Strategy. opts.Cookie defaults to "token".
func New(opts Options) *Strategy {
	cookie := opts.Cookie
	if cookie == "" {
		cookie = "token"
	}
	return &Strategy{cookie: cookie, verify: opts.Verify}
}

// Name returns "cookie-token".
func (s *Strategy) Name() string { return "cookie-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	cookie, err := r.Cookie(s.cookie)
	if err != nil || cookie.Value == "" {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(cookie.Value)
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
