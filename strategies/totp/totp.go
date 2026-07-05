// Package totp implements Time-based One-Time Password (TOTP) authentication as
// specified in RFC 6238 (HMAC-SHA1, 6 digits, 30-second time step). It is the
// Go port of the passport-totp strategy from the Passport.js ecosystem, and is
// the second-factor building block behind the "enter the 6-digit code from your
// authenticator app" experience offered by Google Authenticator, Authy, 1Password,
// and similar apps.
//
// Reach for this package to add a time-based one-time-password second factor
// (2FA/MFA) to an application, or as a passwordless primary factor when the user
// has already enrolled a shared secret. It pairs naturally with a primary
// strategy such as the local username/password strategy: authenticate the
// password first, then require a valid TOTP code before establishing the login
// session. Because the algorithm is fully standardized, any RFC 6238 authenticator
// app interoperates without provider-specific code.
//
// Enrollment happens outside this package: you generate a random shared secret
// per user, store it, and present it to the user (typically as an otpauth:// URI
// rendered as a QR code) so their authenticator app can import it. At sign-in the
// user reads the current 6-digit code from that app and submits it. The Strategy
// reads the user identifier and the code from the request's form/query fields
// (UserField and CodeField, defaulting to "user" and "code"), looks up the secret
// via the Secret callback, and verifies the code.
//
// Verification tolerates clock drift between the server and the authenticator: a
// submitted code is checked against every code valid within Skew time steps on
// either side of the current step (Skew defaults to 1, i.e. the previous, current,
// and next 30-second windows). Comparisons use crypto/subtle constant-time
// equality to avoid timing side channels. The clock is injected through the Now
// option so tests can pin a fixed time; in production it defaults to time.Now.
// Note that TOTP codes are inherently replayable within their window — if you need
// strict one-time use, record accepted (user, step) pairs and reject repeats.
//
// Parity with the Node original is at the algorithm and strategy-contract level:
// like passport-totp you supply a per-user secret lookup and passport records the
// authenticated user on a valid code. The Generate helper is exported so callers
// can build enrollment tooling or verify interoperability, and the fixed
// parameters (Digits, Step, HMAC-SHA1) match the de-facto standard implemented by
// mainstream authenticator apps.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
)

const (
	// Digits is the number of digits in a generated TOTP code.
	Digits = 6
	// Step is the time step over which each TOTP code is valid.
	Step = 30 * time.Second
)

// Generate returns the RFC 6238 TOTP value for the given secret at time t.
func Generate(secret []byte, t time.Time) string {
	counter := uint64(t.Unix()) / uint64(Step.Seconds())
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, bin%mod)
}

// Options configures the totp Strategy.
type Options struct {
	// Secret returns the shared secret for the identified user.
	Secret func(user string) ([]byte, error)
	// UserField names the form/query field carrying the user identifier.
	// Defaults to "user".
	UserField string
	// CodeField names the form/query field carrying the submitted code.
	// Defaults to "code".
	CodeField string
	// Skew is the number of time steps checked on either side of the current
	// step. Defaults to 1.
	Skew int
	// Now returns the current time; defaults to time.Now. Injected for tests.
	Now func() time.Time
}

// Strategy authenticates requests presenting a time-based one-time password.
type Strategy struct {
	secret    func(user string) ([]byte, error)
	userField string
	codeField string
	skew      int
	now       func() time.Time
}

// New creates a totp Strategy, applying defaults for any zero-valued option.
func New(opts Options) *Strategy {
	s := &Strategy{
		secret:    opts.Secret,
		userField: opts.UserField,
		codeField: opts.CodeField,
		skew:      opts.Skew,
		now:       opts.Now,
	}
	if s.userField == "" {
		s.userField = "user"
	}
	if s.codeField == "" {
		s.codeField = "code"
	}
	if s.skew == 0 {
		s.skew = 1
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Name returns "totp".
func (s *Strategy) Name() string { return "totp" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	_ = r.ParseForm()
	user := r.FormValue(s.userField)
	code := r.FormValue(s.codeField)
	if user == "" || code == "" {
		c.Fail("Missing credentials", http.StatusUnauthorized)
		return
	}
	secret, err := s.secret(user)
	if err != nil {
		c.Error(err)
		return
	}
	now := s.now()
	for i := -s.skew; i <= s.skew; i++ {
		expected := Generate(secret, now.Add(time.Duration(i)*Step))
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			c.Success(user)
			return
		}
	}
	c.Fail("Invalid code", http.StatusUnauthorized)
}
