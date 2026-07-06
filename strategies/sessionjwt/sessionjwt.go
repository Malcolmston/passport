// Package sessionjwt implements stateless sessions backed by a signed JWT stored
// in a cookie (default name "session"). It is the cookie-carried, self-contained
// counterpart to a server-side session store: instead of keeping session state
// on the server and referencing it by an opaque ID (as strategies/sessiontoken
// does), the session claims themselves travel in an HS256 JWT signed with
// strategies/jwt.
//
// Use this strategy when you want login sessions without the operational cost of
// a shared session store — the token is self-validating, so any server holding
// the signing secret can authenticate a request with no database round-trip.
// This suits horizontally scaled or serverless deployments. The trade-off is that
// a stateless session cannot be revoked before it expires (short of rotating the
// signing secret); if you need per-session revocation, prefer sessiontoken with a
// real store, or keep a short TTL here.
//
// After a primary login you establish the session by minting a token and setting
// the cookie. Issue builds an HS256 JWT from the given claims, defaulting "iat"
// to now and deriving "exp" from the supplied TTL (a positive TTL overrides any
// "exp" already present). SetCookie writes that token to a cookie named
// CookieName (default "session") with HttpOnly and SameSite=Lax set, Path "/". On
// each subsequent request the strategy reads that cookie; a missing or empty
// cookie is a 401 failure ("no session"). It then parses and verifies the JWT
// (signature and time claims via strategies/jwt); any verification failure,
// including expiry, is a 401 failure ("invalid session"). On success the token's
// claims become the authenticated user.
//
// Options.Secret is the HS256 signing and verification key and must be kept
// secret and be sufficiently long; the same secret is used to issue and to
// verify. Because the cookie is HttpOnly, browser script cannot read it, which
// limits exposure to XSS; serve it Secure over TLS in production. CookieName lets
// you run more than one session cookie side by side.
//
// Parity note: this is a stdlib-only JWT-session pattern rather than a direct
// port of a single Passport.js module; it pairs the JWT verification of
// passport-jwt with cookie storage and helper issuance. Only HS256 (symmetric)
// signing is supported here; for asymmetric verification against a provider's
// keys, see strategies/jwks and strategies/openidconnect.
package sessionjwt

import (
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// DefaultCookie is the cookie name used when Options.Cookie is empty.
const DefaultCookie = "session"

// Options configures the strategy.
type Options struct {
	// Secret is the HS256 signing/verification key.
	Secret []byte
	// Cookie is the cookie name. Defaults to "session".
	Cookie string
}

// Strategy authenticates via a stateless session cookie.
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

// Name returns "session-jwt".
func (s *Strategy) Name() string { return "session-jwt" }

// CookieName returns the configured cookie name.
func (s *Strategy) CookieName() string { return s.cookie }

// Issue mints a session JWT carrying the given claims, with an exp derived from
// ttl (a positive ttl overrides any exp already in claims).
func (s *Strategy) Issue(claims jwt.Claims, ttl time.Duration) (string, error) {
	c := jwt.Claims{}
	for k, v := range claims {
		c[k] = v
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = float64(time.Now().Unix())
	}
	if ttl > 0 {
		c["exp"] = float64(time.Now().Add(ttl).Unix())
	}
	return jwt.Sign(s.secret, c)
}

// SetCookie writes a session cookie holding token to w.
func (s *Strategy) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	ck, err := r.Cookie(s.cookie)
	if err != nil || ck.Value == "" {
		c.Fail("no session", http.StatusUnauthorized)
		return
	}
	parser := jwt.New(s.secret, nil)
	claims, err := parser.Parse(ck.Value)
	if err != nil {
		c.Fail("invalid session", http.StatusUnauthorized)
		return
	}
	c.Success(claims)
}
