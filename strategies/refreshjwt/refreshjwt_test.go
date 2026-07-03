package refreshjwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

var secret = []byte("refresh-secret")

func TestIssueAndAuthenticate(t *testing.T) {
	s := New(Options{Secret: secret})
	tok, err := s.Issue("user-1", time.Hour, jwt.Claims{"role": "admin"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookie, Value: tok})
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(jwt.Claims)
	if claims.Subject() != "user-1" {
		t.Errorf("sub = %q", claims.Subject())
	}
	if claims["role"] != "admin" || claims["typ"] != "refresh" {
		t.Errorf("claims = %v", claims)
	}
}

func TestExpiredToken(t *testing.T) {
	s := New(Options{Secret: secret})
	tok, err := s.Issue("user-1", -time.Minute, nil) // already expired
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookie, Value: tok})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
	if c.Challenge() != "refresh token expired" {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestMissingCookie(t *testing.T) {
	s := New(Options{Secret: secret})
	r := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestCustomCookieName(t *testing.T) {
	s := New(Options{Secret: secret, Cookie: "rt"})
	tok, _ := s.Issue("u", time.Hour, nil)
	r := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "rt", Value: tok})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{}).Name() != "refresh-jwt" {
		t.Error("unexpected name")
	}
}
