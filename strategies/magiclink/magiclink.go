// Package magiclink implements passwordless "magic link" authentication, a
// standard-library-only strategy in the spirit of passport-magic-login. Instead
// of a password, the user proves control of an email address: the application
// mints a signed, time-limited token, emails a link containing it, and the user
// clicks through to be logged in. There is no third-party identity provider and
// no stored password.
//
// Use this strategy when you want frictionless email-based login. It has two
// halves. First, an endpoint you write calls Sign to mint a token for the user's
// email and embeds it in a link (for example
// "https://app.example.com/verify?token=..."), which you deliver by email.
// Second, the verify route you guard with this strategy reads the token from the
// "?token=" query parameter, validates it, and — on success — reports the email
// as the authenticated user for passport to serialize into the session.
//
// The token is self-contained and needs no server-side storage. Its format is:
//
//	base64url(payload) + "." + hex(HMAC-SHA256(payload))
//	payload = "email|expiryUnix"
//
// Validation recomputes the HMAC-SHA256 over the payload with the configured
// Secret and compares it in constant time (hmac.Equal), so a tampered email,
// expiry, or signature is rejected as an HTTP 401 failure. The embedded expiry
// is checked against Now (time.Now by default, injectable for tests); an expired
// token fails. Choose the link lifetime when you call Sign — 15 minutes is a
// reasonable default.
//
// Two security properties deserve emphasis. Expiry bounds the window in which a
// leaked link is useful, so keep it short. Single use, however, is NOT enforced
// by this package: because tokens are stateless, a valid token works repeatedly
// until it expires. If you need strict one-time semantics, record consumed
// tokens (or bump a per-user secret/nonce) in your verify route. Keep the Secret
// random and secret; anyone who learns it can forge a login for any email.
package magiclink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/malcolmston/passport"
)

// Sign builds a magic-link token for email that expires at exp.
func Sign(secret []byte, email string, exp time.Time) string {
	payload := email + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// Options configures the magiclink Strategy.
type Options struct {
	// Secret is the HMAC key used to sign and verify tokens.
	Secret []byte
	// Param names the query parameter carrying the token. Defaults to "token".
	Param string
	// Now returns the current time; defaults to time.Now. Injected for tests.
	Now func() time.Time
}

// Strategy authenticates requests presenting a valid, unexpired magic link.
type Strategy struct {
	secret []byte
	param  string
	now    func() time.Time
}

// New creates a magiclink Strategy.
func New(opts Options) *Strategy {
	param := opts.Param
	if param == "" {
		param = "token"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Strategy{secret: opts.Secret, param: param, now: now}
}

// Name returns "magic-link".
func (s *Strategy) Name() string { return "magic-link" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := r.URL.Query().Get(s.param)
	if token == "" {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	rawPayload, sig := token[:dot], token[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(rawPayload)
	if err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		c.Fail("Invalid signature", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	email := parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	if s.now().Unix() > exp {
		c.Fail("Token expired", http.StatusUnauthorized)
		return
	}
	c.Success(email)
}
