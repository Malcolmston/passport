package custom

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func TestSuccess(t *testing.T) {
	s := New("header-check", func(r *http.Request) (any, error) {
		if r.Header.Get("X-User") == "admin" {
			return map[string]string{"id": "admin"}, nil
		}
		return nil, nil
	})
	if s.Name() != "header-check" {
		t.Errorf("Name = %q", s.Name())
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-User", "admin")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
	if u := c.SuccessUser().(map[string]string); u["id"] != "admin" {
		t.Errorf("user = %v", u)
	}
}

func TestFail(t *testing.T) {
	s := New("header-check", func(r *http.Request) (any, error) {
		return nil, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestError(t *testing.T) {
	boom := errors.New("boom")
	s := New("boom", func(r *http.Request) (any, error) {
		return nil, boom
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError {
		t.Fatalf("want ResultError, got %v", c.Result())
	}
	if !errors.Is(c.Err(), boom) {
		t.Errorf("err = %v", c.Err())
	}
}

func TestNilFuncPasses(t *testing.T) {
	s := New("noop", nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultPass {
		t.Fatalf("want ResultPass, got %v", c.Result())
	}
}
