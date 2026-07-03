package magiclink

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

var secret = []byte("magic-secret")

func fixed(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

func run(token string, now func() time.Time) *passport.Context {
	s := New(Options{Secret: secret, Now: now})
	r := httptest.NewRequest("GET", "/verify?token="+token, nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	token := Sign(secret, "user@example.com", time.Unix(1000, 0))
	c := run(token, fixed(500))
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "user@example.com" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestExpired(t *testing.T) {
	token := Sign(secret, "user@example.com", time.Unix(1000, 0))
	c := run(token, fixed(2000))
	if c.Result() != passport.ResultFail || c.Challenge() != "Token expired" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestTamperedSignature(t *testing.T) {
	token := Sign(secret, "user@example.com", time.Unix(1000, 0))
	c := run(token+"00", fixed(500))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestWrongSecret(t *testing.T) {
	token := Sign([]byte("other"), "user@example.com", time.Unix(1000, 0))
	c := run(token, fixed(500))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	c := run("", fixed(500))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMalformed(t *testing.T) {
	c := run("not-a-token", fixed(500))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Secret: secret}).Name() != "magic-link" {
		t.Fatal("name")
	}
}
