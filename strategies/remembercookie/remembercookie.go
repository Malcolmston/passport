// Package remembercookie implements persistent "remember me" login using the
// selector/validator cookie scheme. The cookie named "remember" holds
// "selector:validatorHMAC". The selector identifies a stored token; the
// validator is compared in constant time against the stored token hash to
// authenticate the user without a password.
package remembercookie

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// CookieName is the name of the remember-me cookie.
const CookieName = "remember"

// LookupFunc resolves a selector to the associated user and the stored hash of
// the validator (tokenHash). It returns a nil user (or an error) when the
// selector is unknown.
type LookupFunc func(selector string) (user any, tokenHash string, err error)

// Options configures the remembercookie Strategy.
type Options struct {
	// Secret is reserved for callers that additionally sign the cookie; it is
	// accepted for API symmetry with the other strategies.
	Secret []byte
	// Lookup resolves the selector to a user and stored validator hash.
	Lookup LookupFunc
}

// Strategy authenticates requests presenting a valid remember-me cookie.
type Strategy struct {
	secret []byte
	lookup LookupFunc
}

// New creates a remembercookie Strategy.
func New(opts Options) *Strategy {
	return &Strategy{secret: opts.Secret, lookup: opts.Lookup}
}

// Name returns "remember-me".
func (s *Strategy) Name() string { return "remember-me" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		c.Pass()
		return
	}
	i := strings.IndexByte(cookie.Value, ':')
	if i < 0 {
		c.Fail("Malformed cookie", http.StatusUnauthorized)
		return
	}
	selector, validator := cookie.Value[:i], cookie.Value[i+1:]

	user, tokenHash, err := s.lookup(selector)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil || tokenHash == "" {
		c.Fail("Invalid token", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(validator), []byte(tokenHash)) != 1 {
		c.Fail("Invalid token", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
