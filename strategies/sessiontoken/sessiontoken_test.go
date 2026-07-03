package sessiontoken

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(token string) (any, error) {
	if token == "good" {
		return "alice", nil
	}
	return nil, ErrInvalidToken
}

func run(cookieName, value string) *passport.Context {
	s := New(Options{Cookie: cookieName, Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	if value != "" {
		name := cookieName
		if name == "" {
			name = "session"
		}
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	c := run("sid", "good")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestDefaultCookieName(t *testing.T) {
	c := run("", "good")
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestInvalid(t *testing.T) {
	c := run("sid", "bad")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	c := run("sid", "")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Verify: verify}).Name() != "session-token" {
		t.Fatal("name")
	}
}
