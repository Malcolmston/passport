package querytoken

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

func run(param, url string) *passport.Context {
	s := New(Options{Param: param, Verify: verify})
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("GET", url, nil))
	return c
}

func TestValid(t *testing.T) {
	c := run("t", "/?t=good")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestDefaultParam(t *testing.T) {
	c := run("", "/?token=good")
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestInvalid(t *testing.T) {
	c := run("t", "/?t=bad")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	c := run("t", "/")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Verify: verify}).Name() != "query-token" {
		t.Fatal("name")
	}
}
