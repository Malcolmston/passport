package bearer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func verifier(t *testing.T) VerifyFunc {
	return func(token string) (any, error) {
		switch token {
		case "good":
			return "user-1", nil
		case "boom":
			return nil, errors.New("backend down")
		case "nil":
			return nil, nil
		default:
			return nil, ErrInvalidToken
		}
	}
}

func run(s *Strategy, r *http.Request) *passport.Context {
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestBearerSuccessFromHeader(t *testing.T) {
	s := New(verifier(t))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer good")
	c := run(s, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "user-1" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestBearerSuccessFromQuery(t *testing.T) {
	s := New(verifier(t))
	c := run(s, httptest.NewRequest(http.MethodGet, "/?access_token=good", nil))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBearerSuccessFromForm(t *testing.T) {
	s := New(verifier(t))
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token=good"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := run(s, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBearerMissingToken(t *testing.T) {
	s := New(verifier(t))
	c := run(s, httptest.NewRequest(http.MethodGet, "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
	if !strings.Contains(c.Challenge(), `realm="Users"`) {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestBearerInvalidToken(t *testing.T) {
	s := New(verifier(t))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	c := run(s, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
	if !strings.Contains(c.Challenge(), "invalid_token") {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestBearerNilUserFails(t *testing.T) {
	s := New(verifier(t))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer nil")
	c := run(s, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBearerVerifyError(t *testing.T) {
	s := New(verifier(t))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer boom")
	c := run(s, r)
	if c.Result() != passport.ResultError {
		t.Fatalf("result=%v (err=%v)", c.Result(), c.Err())
	}
}

func TestBearerCustomRealm(t *testing.T) {
	s := New(verifier(t))
	s.Realm = "API"
	c := run(s, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(c.Challenge(), `realm="API"`) {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestBearerName(t *testing.T) {
	if New(verifier(t)).Name() != "bearer" {
		t.Error("unexpected name")
	}
}
