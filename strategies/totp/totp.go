// Package totp implements Time-based One-Time Password (TOTP) authentication as
// specified in RFC 6238 (SHA1, 6 digits, 30-second time step). A submitted code
// is verified against the codes valid within a configurable skew of time steps
// on either side of the current time, to tolerate clock drift. The clock is
// injected to keep verification deterministic in tests.
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
