package googleidtoken

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

var secret = []byte("google-test-secret")

func signToken(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	tok, err := jwt.Sign(secret, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestSuccessFromQuery(t *testing.T) {
	tok := signToken(t, jwt.Claims{
		"aud": "client-abc",
		"sub": "1234567890",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	s := New(Options{Secret: secret, Audience: "client-abc"})

	r := httptest.NewRequest(http.MethodGet, "/verify?id_token="+url.QueryEscape(tok), nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(jwt.Claims)
	if claims.Subject() != "1234567890" {
		t.Errorf("sub = %q", claims.Subject())
	}
}

func TestSuccessFromForm(t *testing.T) {
	tok := signToken(t, jwt.Claims{
		"aud": "client-abc",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	body := "id_token=" + url.QueryEscape(tok)
	r := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s := New(Options{Secret: secret, Audience: "client-abc"})
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
}

func TestWrongAudience(t *testing.T) {
	tok := signToken(t, jwt.Claims{
		"aud": "other-client",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	s := New(Options{Secret: secret, Audience: "client-abc"})
	r := httptest.NewRequest(http.MethodGet, "/verify?id_token="+url.QueryEscape(tok), nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestExpired(t *testing.T) {
	tok := signToken(t, jwt.Claims{
		"aud": "client-abc",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	s := New(Options{Secret: secret, Audience: "client-abc"})
	r := httptest.NewRequest(http.MethodGet, "/verify?id_token="+url.QueryEscape(tok), nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestMissingToken(t *testing.T) {
	s := New(Options{Secret: secret})
	r := httptest.NewRequest(http.MethodGet, "/verify", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{}).Name() != "google-id-token" {
		t.Error("unexpected name")
	}
}
