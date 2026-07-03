package refreshtoken

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(token string) (any, error) {
	if token == "good" {
		return "alice", nil
	}
	return nil, ErrInvalidToken
}

func TestFormBody(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", strings.NewReader("refresh_token=good&grant_type=refresh_token"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
	// Body restored.
	rest, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(rest), "refresh_token=good") {
		t.Fatalf("body not restored: %q", rest)
	}
}

func TestJSONBody(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", strings.NewReader(`{"refresh_token":"good"}`))
	r.Header.Set("Content-Type", "application/json")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestInvalid(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", strings.NewReader("refresh_token=bad"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(verify).Name() != "refresh-token" {
		t.Fatal("name")
	}
}
