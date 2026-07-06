// Package bearer implements HTTP Bearer token authentication (RFC 6750) for the
// passport port. It is a Go port of passport-http-bearer: a client presents an
// opaque access token and a user-supplied VerifyFunc resolves it to an
// application user. It is the classic way to protect an OAuth2-style API where
// tokens are issued elsewhere and merely validated here.
//
// Use it to guard API endpoints consumed by single-page apps, mobile clients or
// other services that hold an access token. It creates no session and is
// normally mounted with passport.Options{Session: false}; the token, not a
// cookie, authenticates every request.
//
// The token is extracted, in order, from the "Authorization: Bearer <token>"
// header, the access_token query parameter, or (for non-GET requests) the
// access_token form field — matching the three token locations RFC 6750 defines.
// A request with no token fails with a 401 and a Bearer realm="<Realm>"
// challenge; the Realm field defaults to "Users".
//
// The VerifyFunc contract has three outcomes: a non-nil user authenticates the
// request; (nil, nil) or (nil, ErrInvalidToken) rejects it with a Bearer
// challenge carrying error="invalid_token"; and (nil, err) for any other error
// is treated as an internal error. Note that the query- and form-based token
// locations are convenient but can leak tokens into logs and referrers, so prefer
// the header in production and always serve over HTTPS.
//
// Parity: this follows passport-http-bearer's extraction rules and challenge
// format. The optional info/scope value that the Node verify callback can pass
// alongside the user is not modeled — VerifyFunc returns just the user — and
// token issuance, storage and expiry are left to the caller.
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
