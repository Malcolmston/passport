// Package sessionjwt implements stateless sessions backed by a signed JWT stored
// in a cookie (default name "session"). Instead of a server-side session store,
// the session claims travel in an HS256 JWT (via strategies/jwt); the strategy
// verifies the cookie's token and, on success, makes its claims the
// authenticated user.
//
// Issue and SetCookie are convenience helpers for establishing a session after
// a primary login.
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
