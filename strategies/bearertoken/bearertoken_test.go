package bearertoken

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(token string) (any, error) {
	switch token {
	case "good":
		return "svc", nil
	case "boom":
		return nil, errors.New("db down")
	default:
		return nil, ErrInvalidToken
	}
}

func TestValid(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer good")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "svc" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestCaseInsensitiveScheme(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer good")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(verify)
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("GET", "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestInvalid(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer bad")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestError(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer boom")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError || c.Err() == nil {
		t.Fatalf("result=%v err=%v", c.Result(), c.Err())
	}
}

func TestName(t *testing.T) {
	if New(verify).Name() != "bearer-token" {
		t.Fatal("name")
	}
}
