package local

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func bodyOf(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

func run(s *Strategy, r *http.Request) *passport.Context {
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestVerifySuccess(t *testing.T) {
	s := New(func(u, p string) (any, error) {
		if u == "bob" && p == "pw" {
			return "bob-user", nil
		}
		return nil, ErrInvalidCredentials
	})
	r, _ := http.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Body = bodyOf(`{"username":"bob","password":"pw"}`)

	c := run(s, r)
	got := c.SuccessUser()
	if got != "bob-user" {
		t.Fatalf("expected success with bob-user, got %v (result=%v)", got, c.Result())
	}
}

func TestMissingCredentials(t *testing.T) {
	s := New(func(u, p string) (any, error) { return "x", nil })
	r, _ := http.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := run(s, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("expected fail for missing creds, got %v", c.Result())
	}
}

func TestCustomFieldNames(t *testing.T) {
	s := New(func(u, p string) (any, error) {
		if u == "e@x.com" && p == "hunter2" {
			return "ok", nil
		}
		return nil, ErrInvalidCredentials
	})
	s.UsernameField = "email"
	s.PasswordField = "pass"

	r, _ := http.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Body = bodyOf(`{"email":"e@x.com","pass":"hunter2"}`)
	c := run(s, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("expected success with custom fields, got %v", c.Result())
	}
}
