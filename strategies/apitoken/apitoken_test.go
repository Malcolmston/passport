package apitoken

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func TestLookupSuccess(t *testing.T) {
	store := map[string]string{"tok-123": "alice"}
	s := New(Options{Lookup: func(token string) (any, bool) {
		u, ok := store[token]
		return u, ok
	}})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer tok-123")
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
	if c.SuccessUser() != "alice" {
		t.Errorf("user = %v", c.SuccessUser())
	}
}

func TestLookupUnknownToken(t *testing.T) {
	s := New(Options{Lookup: func(token string) (any, bool) { return nil, false }})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Token", "nope")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestStaticTokenConstantTime(t *testing.T) {
	s := New(Options{Token: "s3cr3t", User: "svc"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Token s3cr3t")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "svc" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestStaticTokenMismatch(t *testing.T) {
	s := New(Options{Token: "s3cr3t", User: "svc"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Token", "wrong")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestMissingToken(t *testing.T) {
	s := New(Options{Token: "x"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings reported unequal")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Error("unequal strings reported equal")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Error("different-length strings reported equal")
	}
}

func TestName(t *testing.T) {
	if New(Options{}).Name() != "api-token" {
		t.Error("unexpected name")
	}
}
