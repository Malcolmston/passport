package jwtbearer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

var secret = []byte("bearer-secret")

func TestSuccess(t *testing.T) {
	assertion, err := jwt.Sign(secret, jwt.Claims{
		"iss": "client@example.com",
		"sub": "svc-account",
		"exp": float64(time.Now().Add(time.Minute).Unix()),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	form := url.Values{"grant_type": {GrantType}, "assertion": {assertion}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s := New(Options{Secret: secret})
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(jwt.Claims)
	if claims.Subject() != "svc-account" {
		t.Errorf("sub = %q", claims.Subject())
	}
}

func TestMissingAssertion(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s := New(Options{Secret: secret})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestBadSignature(t *testing.T) {
	assertion, _ := jwt.Sign([]byte("nope"), jwt.Claims{
		"sub": "x",
		"exp": float64(time.Now().Add(time.Minute).Unix()),
	})
	form := url.Values{"assertion": {assertion}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s := New(Options{Secret: secret})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{}).Name() != "jwt-bearer" {
		t.Error("unexpected name")
	}
}
