// Package hotp implements HMAC-based One-Time Password (HOTP) authentication as
// specified in RFC 4226. A submitted 6-digit code is verified against the
// codes derived from a per-user shared secret and counter, tolerating a
// forward look-ahead window to account for the client and server counters
// drifting apart.
package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/http"

	"github.com/malcolmston/passport"
)

// Digits is the number of digits in a generated HOTP code.
const Digits = 6

// Generate returns the RFC 4226 HOTP value for the given secret and counter.
func Generate(secret []byte, counter uint64) string {
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

// Options configures the hotp Strategy.
type Options struct {
	// Secret returns the shared secret for the identified user.
	Secret func(user string) ([]byte, error)
	// Counter returns the current expected counter value for the user.
	Counter func(user string) (uint64, error)
	// UserField names the form/query field carrying the user identifier.
	// Defaults to "user".
	UserField string
	// CodeField names the form/query field carrying the submitted code.
	// Defaults to "code".
	CodeField string
	// Window is the number of counter values to look ahead. Defaults to 3.
	Window int
}

// Strategy authenticates requests presenting a counter-based one-time password.
type Strategy struct {
	secret    func(user string) ([]byte, error)
	counter   func(user string) (uint64, error)
	userField string
	codeField string
	window    int
}

// New creates an hotp Strategy, applying defaults for any zero-valued option.
func New(opts Options) *Strategy {
	s := &Strategy{
		secret:    opts.Secret,
		counter:   opts.Counter,
		userField: opts.UserField,
		codeField: opts.CodeField,
		window:    opts.Window,
	}
	if s.userField == "" {
		s.userField = "user"
	}
	if s.codeField == "" {
		s.codeField = "code"
	}
	if s.window == 0 {
		s.window = 3
	}
	return s
}

// Name returns "hotp".
func (s *Strategy) Name() string { return "hotp" }

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
	counter, err := s.counter(user)
	if err != nil {
		c.Error(err)
		return
	}
	for i := 0; i <= s.window; i++ {
		expected := Generate(secret, counter+uint64(i))
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			c.Success(user)
			return
		}
	}
	c.Fail("Invalid code", http.StatusUnauthorized)
}
