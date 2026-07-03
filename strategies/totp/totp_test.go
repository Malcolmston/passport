package totp

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

// RFC 6238 Appendix B SHA1 vectors, truncated to 6 digits.
func TestGenerateRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		if got := Generate(secret, time.Unix(c.unix, 0)); got != c.want {
			t.Errorf("unix %d: got %s want %s", c.unix, got, c.want)
		}
	}
}

func fixed(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

func opts(now func() time.Time) Options {
	return Options{
		Secret: func(u string) ([]byte, error) { return []byte("12345678901234567890"), nil },
		Now:    now,
	}
}

func post(s *Strategy, user, code string) *passport.Context {
	form := url.Values{"user": {user}, "code": {code}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	s := New(opts(fixed(59)))
	c := post(s, "alice", "287082")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestSkewPrevWindow(t *testing.T) {
	// Code valid at t=59 accepted when now=89 (one step later, skew=1).
	s := New(opts(fixed(89)))
	c := post(s, "alice", "287082")
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestOutsideSkew(t *testing.T) {
	// Two steps away is rejected with default skew=1.
	s := New(opts(fixed(119)))
	c := post(s, "alice", "287082")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestWrongCode(t *testing.T) {
	s := New(opts(fixed(59)))
	c := post(s, "alice", "000000")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(opts(fixed(59)))
	c := post(s, "", "")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(opts(fixed(0))).Name() != "totp" {
		t.Fatal("name")
	}
}
