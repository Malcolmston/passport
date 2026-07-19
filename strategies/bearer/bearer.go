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

	// Scope, when non-empty, is advertised in the WWW-Authenticate challenge
	// as scope="<space-joined>", indicating the scope required to access the
	// protected resource (RFC 6750 §3).
	Scope []string

	verify VerifyFunc
}

// New creates a bearer Strategy. It panics if verify is nil, matching
// passport-http-bearer, which throws "HTTPBearerStrategy requires a verify
// function".
func New(verify VerifyFunc) *Strategy {
	if verify == nil {
		panic("bearer: New requires a verify function")
	}
	return &Strategy{Realm: "Users", verify: verify}
}

// Name returns "bearer".
func (s *Strategy) Name() string { return "bearer" }

// Authenticate implements passport.Strategy. It mirrors passport-http-bearer's
// token extraction: at most one of the Authorization header, the access_token
// body parameter, or the access_token query parameter may carry the token.
// Presenting a Bearer header without a token, or a token in more than one
// location, is a malformed request and fails with HTTP 400.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	var token string

	if h := r.Header.Get("Authorization"); h != "" {
		parts := strings.Split(h, " ")
		if len(parts) == 2 {
			if strings.EqualFold(parts[0], "Bearer") {
				token = parts[1]
			}
		} else {
			c.Fail("", http.StatusBadRequest)
			return
		}
	}

	if bt := bodyToken(r); bt != "" {
		if token != "" {
			c.Fail("", http.StatusBadRequest)
			return
		}
		token = bt
	}

	if qt := r.URL.Query().Get("access_token"); qt != "" {
		if token != "" {
			c.Fail("", http.StatusBadRequest)
			return
		}
		token = qt
	}

	if token == "" {
		c.Fail(s.challenge(""), http.StatusUnauthorized)
		return
	}

	user, err := s.verify(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail(s.challenge("invalid_token"), http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail(s.challenge("invalid_token"), http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// challenge builds the WWW-Authenticate value, mirroring the upstream
// _challenge() helper: realm, then optional scope, then optional error code.
func (s *Strategy) challenge(code string) string {
	ch := `Bearer realm="` + s.Realm + `"`
	if len(s.Scope) > 0 {
		ch += `, scope="` + strings.Join(s.Scope, " ") + `"`
	}
	if code != "" {
		ch += `, error="` + code + `"`
	}
	return ch
}

// bodyToken returns the access_token from a form-encoded request body only
// (never the query string), matching upstream's req.body.access_token check.
func bodyToken(r *http.Request) string {
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.PostForm.Get("access_token")
}
