package remembercookie

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func lookup(selector string) (any, string, error) {
	switch selector {
	case "sel1":
		return "alice", "validhash", nil
	case "boom":
		return nil, "", errors.New("db down")
	default:
		return nil, "", nil
	}
}

func withCookie(value string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	if value != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: value})
	}
	return r
}

func run(value string) *passport.Context {
	s := New(Options{Lookup: lookup})
	c := &passport.Context{}
	s.Authenticate(c, withCookie(value))
	return c
}

func TestValid(t *testing.T) {
	c := run("sel1:validhash")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestBadValidator(t *testing.T) {
	c := run("sel1:wrong")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestUnknownSelector(t *testing.T) {
	c := run("nope:whatever")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestNoCookie(t *testing.T) {
	c := run("")
	if c.Result() != passport.ResultPass {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMalformed(t *testing.T) {
	c := run("no-colon")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestLookupError(t *testing.T) {
	c := run("boom:x")
	if c.Result() != passport.ResultError || c.Err() == nil {
		t.Fatalf("result=%v err=%v", c.Result(), c.Err())
	}
}

func TestName(t *testing.T) {
	if New(Options{Lookup: lookup}).Name() != "remember-me" {
		t.Fatal("name")
	}
}
