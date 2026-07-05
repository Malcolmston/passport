// Package hotp implements HMAC-based One-Time Password (HOTP) authentication as
// specified in RFC 4226, packaged as a passport.Strategy whose Name is "hotp".
// It is the Go analogue of Node's passport-hotp strategy and provides the
// counter-based counterpart to time-based (TOTP) one-time passwords: the same
// codes produced by RFC 4226 authenticator apps and hardware tokens.
//
// Use this strategy for a second authentication factor, or a primary one, where
// each valid login consumes the next code in a per-user sequence rather than a
// code tied to the wall clock. HOTP suits hardware tokens and offline devices
// that have no reliable clock but can maintain a monotonically increasing
// counter, and it avoids the time-synchronization requirements of TOTP.
//
// On each request the strategy reads the user identifier from Options.UserField
// (default "user") and the submitted code from Options.CodeField (default
// "code"), taken from the form or query. It looks up the user's shared secret
// via Options.Secret and the current expected counter via Options.Counter, then
// computes the expected 6-digit code (const Digits = 6, exposed by Generate) for
// each counter value from the current counter up to counter+Window. The
// submitted code is compared against each candidate with a constant-time
// comparison (crypto/subtle) to avoid leaking timing information; a match
// authenticates the user id, and no match yields a 401.
//
// The forward look-ahead Window (default 3) tolerates counter drift between the
// client and server: because a token can advance its counter — for example when
// a user generates codes that never reach the server — the server accepts a code
// slightly ahead of its own counter. Widening the window increases tolerance at
// the cost of accepting more candidate codes, so it should be kept small. The
// window only looks forward; codes for counters already behind the server are
// never accepted.
//
// A critical responsibility falls on the caller rather than the strategy: HOTP
// codes are single-use, so after a successful authentication the application
// must advance the stored counter past the code that was just accepted
// (Options.Counter must then return the new value), otherwise the same code
// could be replayed. The Secret and Counter provider functions abstract this
// per-user state so it can live in whatever store the application uses. This
// division of labor — verify here, advance the counter in the success handler —
// mirrors the semantics of the passport-hotp strategy and RFC 4226.
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
