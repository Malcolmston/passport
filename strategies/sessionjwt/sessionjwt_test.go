package sessionjwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

var secret = []byte("session-secret")

func TestIssueSetCookieAndAuthenticate(t *testing.T) {
	s := New(Options{Secret: secret})
	tok, err := s.Issue(jwt.Claims{"sub": "u42", "name": "Dana"}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Round-trip through SetCookie -> request cookie.
	rec := httptest.NewRecorder()
	s.SetCookie(rec, tok)
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultCookie {
		t.Fatalf("SetCookie wrote %v", cookies)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookies[0])
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(jwt.Claims)
	if claims.Subject() != "u42" || claims["name"] != "Dana" {
		t.Errorf("claims = %v", claims)
	}
}

func TestNoCookie(t *testing.T) {
	s := New(Options{Secret: secret})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestTamperedCookie(t *testing.T) {
	s := New(Options{Secret: secret})
	other := New(Options{Secret: []byte("different")})
	tok, _ := other.Issue(jwt.Claims{"sub": "x"}, time.Hour)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookie, Value: tok})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestCustomCookie(t *testing.T) {
	s := New(Options{Secret: secret, Cookie: "sess"})
	if s.CookieName() != "sess" {
		t.Errorf("CookieName = %q", s.CookieName())
	}
	tok, _ := s.Issue(jwt.Claims{"sub": "u"}, 0)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sess", Value: tok})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{}).Name() != "session-jwt" {
		t.Error("unexpected name")
	}
}
