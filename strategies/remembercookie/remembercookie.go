// Package remembercookie implements persistent "remember me" login using the
// selector/validator cookie scheme. It ports the intent of Passport.js's
// passport-remember-me strategy: it lets a returning visitor be recognized and
// logged in automatically from a long-lived cookie, without re-entering their
// password, even after their session has expired.
//
// Use this strategy alongside your primary login. When a user checks a "remember
// me" box, you generate a fresh token (a random selector plus a random
// validator), store the selector together with a hash of the validator keyed to
// the user, and set a persistent cookie holding "selector:validator". On a later
// visit with no active session, this strategy consults that cookie to
// re-establish the login. It is intentionally non-fatal when absent: with no
// remember cookie the strategy calls Pass() so the request continues as an
// anonymous visitor rather than failing.
//
// The cookie is named CookieName ("remember") and holds "selector:validator".
// The selector is the lookup key and the validator is the secret. On each request
// the strategy splits the cookie at the first ':'; a value with no ':' is a 401
// failure ("Malformed cookie"). It then calls the LookupFunc with the selector,
// which returns the associated user and the stored token hash. An unknown
// selector (nil user or empty hash) is a 401 failure ("Invalid token"), and any
// error from the lookup is reported as an internal error. The presented validator
// is compared against the stored hash using crypto/subtle constant-time
// comparison to avoid leaking timing information; only an exact match yields
// Success.
//
// The selector/validator split is what makes the scheme safe: the selector is
// used for the database lookup (so lookups are not vulnerable to timing attacks),
// while the validator is the actual secret and is only ever stored hashed. This
// also lets you revoke a single remembered device by deleting its selector row,
// and mitigates theft by rotating the validator on each use. Options.Secret is
// accepted for API symmetry with the other strategies (for callers that
// additionally sign the cookie) but is not required by the core comparison.
//
// Security and parity notes: set the cookie as HttpOnly, Secure and with a long
// but bounded Max-Age/Expires, and rotate the validator (issue a new one and
// invalidate the old) on every successful auto-login so a stolen cookie is
// single-use. Treat a valid selector with a mismatched validator as a possible
// theft and consider invalidating all of that user's remember tokens. Minting,
// storing, hashing and rotating tokens are the application's responsibility; this
// strategy focuses on the read/verify half, matching the deliberately minimal
// design of the Go port.
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
