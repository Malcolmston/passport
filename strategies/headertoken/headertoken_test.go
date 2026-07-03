package headertoken

import (
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

func run(header, setHeader, value string) *passport.Context {
	s := New(Options{Header: header, Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	if value != "" {
		r.Header.Set(setHeader, value)
	}
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	c := run("X-Token", "X-Token", "good")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestDefaultHeader(t *testing.T) {
	c := run("", "X-Auth-Token", "good")
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestInvalid(t *testing.T) {
	c := run("X-Token", "X-Token", "bad")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	c := run("X-Token", "X-Token", "")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Verify: verify}).Name() != "header-token" {
		t.Fatal("name")
	}
}
