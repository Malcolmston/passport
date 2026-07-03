// Package refreshjwt authenticates a request using a refresh-token JWT carried
// in a cookie (default name "refresh_token"). The token is an HS256 JWT
// (verified via strategies/jwt); on success its claims become the authenticated
// user, and an expired token yields an authentication failure so the client
// knows to re-authenticate.
//
// Issue is provided as a convenience for minting refresh tokens with a chosen
// TTL; it is the counterpart used by the tests and by token-issuing endpoints.
package refreshjwt

import (
	"errors"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// DefaultCookie is the cookie name used when Options.Cookie is empty.
const DefaultCookie = "refresh_token"

// Options configures the strategy.
type Options struct {
	// Secret is the HS256 signing/verification key.
	Secret []byte
	// Cookie is the cookie name. Defaults to "refresh_token".
	Cookie string
}

// Strategy authenticates via a refresh-token cookie.
type Strategy struct {
	secret []byte
	cookie string
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	cookie := opts.Cookie
	if cookie == "" {
		cookie = DefaultCookie
	}
	return &Strategy{secret: opts.Secret, cookie: cookie}
}

// Name returns "refresh-jwt".
func (s *Strategy) Name() string { return "refresh-jwt" }

// Issue mints a refresh JWT for subject with the given TTL and optional extra
// claims. A "typ":"refresh" claim is set to distinguish it from access tokens.
func (s *Strategy) Issue(subject string, ttl time.Duration, extra jwt.Claims) (string, error) {
	claims := jwt.Claims{
		"sub": subject,
		"typ": "refresh",
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(ttl).Unix()),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return jwt.Sign(s.secret, claims)
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	ck, err := r.Cookie(s.cookie)
	if err != nil || ck.Value == "" {
		c.Fail("missing refresh token", http.StatusUnauthorized)
		return
	}

	parser := jwt.New(s.secret, nil)
	claims, err := parser.Parse(ck.Value)
	if err != nil {
		// Expiry and other verification failures are authentication failures.
		if errors.Is(err, jwt.ErrExpired) {
			c.Fail("refresh token expired", http.StatusUnauthorized)
			return
		}
		c.Fail("invalid refresh token", http.StatusUnauthorized)
		return
	}
	c.Success(claims)
}
