package apikey

import (
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(key string) (any, error) {
	if key == "good" {
		return "svc", nil
	}
	return nil, ErrInvalidKey
}

func TestHeaderSuccess(t *testing.T) {
	s := New(Options{Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", "good")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v", c.Result())
	}
	if c.SuccessUser() != "svc" {
		t.Fatalf("user = %v", c.SuccessUser())
	}
}

func TestCustomHeader(t *testing.T) {
	s := New(Options{Header: "Api-Token", Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Api-Token", "good")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestQueryFallback(t *testing.T) {
	s := New(Options{Query: "api_key", Verify: verify})
	r := httptest.NewRequest("GET", "/?api_key=good", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(Options{Verify: verify})
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("GET", "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v", c.Result())
	}
	if c.Challenge() == "" {
		t.Fatal("expected challenge")
	}
}

func TestInvalid(t *testing.T) {
	s := New(Options{Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", "bad")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestDefaultHeaderName(t *testing.T) {
	if New(Options{}).header != "X-API-Key" {
		t.Fatal("default header not applied")
	}
}
