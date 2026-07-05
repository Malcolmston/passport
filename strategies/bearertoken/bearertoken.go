// Package bearertoken implements opaque bearer-token authentication via token
// introspection for the passport port. It is a focused variant of the
// passport-http-bearer idea: the token is read only from the standard
// "Authorization: Bearer <token>" header and handed to a user-supplied VerifyFunc
// that introspects it — against a local token store, a cache, or a remote
// RFC 7662 introspection endpoint.
//
// Reach for this strategy when tokens are validated by asking an authority
// whether they are still active, rather than by verifying a self-contained
// signature (for which a JWT strategy is more appropriate). It suits API gateways
// and resource servers in an OAuth2 deployment; like the other token strategies
// it is stateless and typically mounted with passport.Options{Session: false}.
//
// On each request the strategy requires a well-formed "Bearer " Authorization
// header. If the header is absent, uses a different scheme, or carries an empty
// token, the request fails with a 401 "Bearer" challenge before VerifyFunc runs.
// Unlike strategies/bearer it does not consult the query string or form body: the
// token must be in the header.
//
// The VerifyFunc contract has three outcomes: a non-nil user authenticates the
// request; (nil, nil) or (nil, ErrInvalidToken) rejects it with a Bearer
// error="invalid_token" challenge; and (nil, err) is treated as an internal error
// and surfaced via the context. Introspection results are often cacheable for the
// token's lifetime, which is a decision left to the VerifyFunc.
//
// Parity: this maps to passport-http-bearer's header handling while narrowing the
// token source to the Authorization header only and framing the callback as an
// introspection step. It registers under the name "bearer-token" so it can be
// used alongside the header/query/form-capable strategies/bearer package.
package bearertoken

import (
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a Verify func may return to signal
// an invalid or expired token (treated as an authentication failure).
var ErrInvalidToken = errors.New("invalid token")

// VerifyFunc introspects an opaque token, returning the authenticated user on
// success.
type VerifyFunc func(token string) (user any, err error)

// Strategy authenticates requests bearing an opaque access token.
type Strategy struct {
	verify VerifyFunc
}

// New creates a bearertoken Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{verify: verify}
}

// Name returns "bearer-token".
func (s *Strategy) Name() string { return "bearer-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
