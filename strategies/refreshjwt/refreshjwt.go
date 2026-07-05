// Package refreshjwt authenticates a request using a refresh-token JWT carried
// in a cookie (default name "refresh_token"). It fills the same role as the
// refresh-token half of the JWT-based session patterns in the Passport.js
// ecosystem: a long-lived, signed credential that lets a client obtain fresh
// short-lived access tokens without re-entering their password.
//
// Use this strategy for the token-refresh endpoint of an API. A typical setup
// issues a short-lived access token (checked by strategies/jwt or bearer) plus a
// long-lived refresh JWT stored in an HttpOnly cookie; when the access token
// expires, the client calls the refresh endpoint, this strategy validates the
// refresh cookie, and the handler mints a new access token. Keeping the refresh
// token in a self-contained JWT means the server does not need a database lookup
// to validate it, at the cost of not being able to revoke an individual token
// before it expires.
//
// The token is an HS256 JWT verified via strategies/jwt using Options.Secret.
// On each request the strategy reads the cookie named Options.Cookie (default
// "refresh_token"); a missing or empty cookie is a 401 failure ("missing refresh
// token"). It then parses and verifies the JWT: on success the token's claims
// become the authenticated user. Signature and other verification failures are
// reported as a 401 ("invalid refresh token"), and an expired token
// (jwt.ErrExpired) is reported as a distinct 401 ("refresh token expired") so the
// client knows to start a full re-authentication rather than retry.
//
// Issue is provided as a convenience for minting refresh tokens with a chosen
// TTL; it is the counterpart used by the tests and by token-issuing endpoints.
// It sets standard "sub", "iat" and "exp" claims plus a "typ":"refresh" marker
// (which distinguishes refresh tokens from access tokens), merges any extra
// claims you pass, and signs the result with the strategy's secret.
//
// Security and parity notes: because validation is purely cryptographic there is
// no built-in revocation, rotation, or reuse-detection — if you need to revoke or
// rotate refresh tokens, track a token identifier (jti) or version in a store and
// check it in your refresh handler after this strategy authenticates the cookie.
// Always store the cookie as HttpOnly, Secure and SameSite to limit exfiltration,
// and scope it to the refresh path. This mirrors the deliberately minimal,
// stdlib-only design of the Go port rather than any single Node module.
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
