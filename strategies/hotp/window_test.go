package hotp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

var otpSecret = []byte("12345678901234567890")

func submit(t *testing.T, s *Strategy, user, code string) *passport.Context {
	t.Helper()
	form := url.Values{"user": {user}, "code": {code}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func strategyWithWindow(window int, counter uint64) *Strategy {
	return New(Options{
		Secret:  func(string) ([]byte, error) { return otpSecret, nil },
		Counter: func(string) (uint64, error) { return counter, nil },
		Window:  window,
	})
}

// TestRFC4226Vectors checks Generate against the full table in RFC 4226
// Appendix D.
func TestRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, code := range want {
		if got := Generate(otpSecret, uint64(counter)); got != code {
			t.Errorf("Generate(counter=%d) = %q, want %q", counter, got, code)
		}
	}
}

// TestLookAheadWindow covers counter drift, including the negative-window case.
// A negative Window used to make the verification loop run zero times, so every
// code was silently rejected. It is now read as the strict setting instead.
//
// The window must only look forward: a code for a counter the server has
// already passed is exactly the replay HOTP exists to prevent.
func TestLookAheadWindow(t *testing.T) {
	const stored = 5

	cases := []struct {
		name    string
		window  int
		counter uint64
		want    passport.Result
	}{
		{"default accepts exact counter", 0, stored, passport.ResultSuccess},
		{"default accepts within look-ahead", 0, stored + 3, passport.ResultSuccess},
		{"default rejects beyond look-ahead", 0, stored + 4, passport.ResultFail},
		{"default rejects a consumed counter", 0, stored - 1, passport.ResultFail},
		{"wide window accepts further ahead", 10, stored + 9, passport.ResultSuccess},
		{"wide window still rejects behind", 10, stored - 1, passport.ResultFail},
		{"negative window accepts exact counter", -1, stored, passport.ResultSuccess},
		{"negative window rejects look-ahead", -1, stored + 1, passport.ResultFail},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := strategyWithWindow(tt.window, stored)
			c := submit(t, s, "alice", Generate(otpSecret, tt.counter))
			if c.Result() != tt.want {
				t.Errorf("Result() = %v, want %v", c.Result(), tt.want)
			}
		})
	}
}

// TestMissingCredentials checks the paths that must fail before any lookup.
func TestMissingCredentials(t *testing.T) {
	s := strategyWithWindow(0, 5)
	for _, tt := range []struct{ user, code string }{
		{"", "123456"},
		{"alice", ""},
		{"", ""},
	} {
		if c := submit(t, s, tt.user, tt.code); c.Result() != passport.ResultFail {
			t.Errorf("user=%q code=%q: Result() = %v, want fail", tt.user, tt.code, c.Result())
		}
	}
}
