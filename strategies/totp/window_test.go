package totp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

func strategyWithSkew(skew int, now time.Time) *Strategy {
	return New(Options{
		Secret: func(string) ([]byte, error) { return otpSecret, nil },
		Skew:   skew,
		Now:    func() time.Time { return now },
	})
}

// TestSkewWindow covers the drift tolerance, including the negative-skew case.
// A negative Skew used to make the verification loop run zero times, so every
// code was silently rejected — a misconfiguration indistinguishable from a
// wrong shared secret. It is now read as the strict setting instead.
func TestSkewWindow(t *testing.T) {
	now := time.Unix(1_000_000_000, 0)
	prev := Generate(otpSecret, now.Add(-Step))
	cur := Generate(otpSecret, now)
	next := Generate(otpSecret, now.Add(Step))
	far := Generate(otpSecret, now.Add(3*Step))

	cases := []struct {
		name string
		skew int
		code string
		want passport.Result
	}{
		{"default accepts current", 0, cur, passport.ResultSuccess},
		{"default accepts previous", 0, prev, passport.ResultSuccess},
		{"default accepts next", 0, next, passport.ResultSuccess},
		{"default rejects far", 0, far, passport.ResultFail},
		{"wide window accepts far", 3, far, passport.ResultSuccess},
		{"negative skew still accepts current", -1, cur, passport.ResultSuccess},
		{"negative skew rejects previous", -1, prev, passport.ResultFail},
		{"negative skew rejects next", -1, next, passport.ResultFail},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := submit(t, strategyWithSkew(tt.skew, now), "alice", tt.code)
			if c.Result() != tt.want {
				t.Errorf("Result() = %v, want %v", c.Result(), tt.want)
			}
		})
	}
}

// TestRFC4226Vector checks Generate against the published HOTP value for
// counter 1, which a 30-second TOTP step reaches at t=30.
func TestRFC4226Vector(t *testing.T) {
	if got := Generate(otpSecret, time.Unix(30, 0)); got != "287082" {
		t.Errorf("Generate at counter 1 = %q, want 287082", got)
	}
	if got := Generate(otpSecret, time.Unix(0, 0)); got != "755224" {
		t.Errorf("Generate at counter 0 = %q, want 755224", got)
	}
}

// TestMissingCredentials checks the paths that must fail before the secret
// lookup happens.
func TestMissingCredentials(t *testing.T) {
	now := time.Unix(1_000_000_000, 0)
	s := strategyWithSkew(0, now)
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
