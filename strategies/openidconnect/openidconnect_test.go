package openidconnect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

var secret = []byte("oidc-shared-secret")

func TestAuthenticateRedirect(t *testing.T) {
	s := New(Config{
		ClientID:    "cid",
		RedirectURL: "https://app.example/cb",
		AuthURL:     "https://idp.example/authorize",
		Scopes:      []string{"email", "profile"},
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/login?state=st", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultRedirect {
		t.Fatalf("want ResultRedirect, got %v", c.Result())
	}
	if got := s.scope(); got != "openid email profile" {
		t.Errorf("scope = %q", got)
	}
}

func TestAuthenticateCodeExchangeSuccess(t *testing.T) {
	idToken, err := jwt.Sign(secret, jwt.Claims{
		"iss": "https://idp.example",
		"sub": "user-123",
		"aud": "cid",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}

	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" {
			t.Errorf("code = %q", r.PostForm.Get("code"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"` + idToken + `"}`))
	}))
	defer token.Close()

	s := New(Config{
		Issuer:      "https://idp.example",
		ClientID:    "cid",
		TokenURL:    token.URL,
		JWKSecret:   secret,
		HTTPClient:  token.Client(),
		RedirectURL: "https://app.example/cb",
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/cb?code=the-code", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims, ok := c.SuccessUser().(jwt.Claims)
	if !ok {
		t.Fatalf("SuccessUser type = %T", c.SuccessUser())
	}
	if claims.Subject() != "user-123" {
		t.Errorf("sub = %q", claims.Subject())
	}
}

func TestAuthenticateBadIssuer(t *testing.T) {
	idToken, _ := jwt.Sign(secret, jwt.Claims{
		"iss": "https://evil.example",
		"sub": "u",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id_token":"` + idToken + `"}`))
	}))
	defer token.Close()

	s := New(Config{
		Issuer:     "https://idp.example",
		ClientID:   "cid",
		TokenURL:   token.URL,
		JWKSecret:  secret,
		HTTPClient: token.Client(),
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/cb?code=x", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestAuthenticateBadSignature(t *testing.T) {
	idToken, _ := jwt.Sign([]byte("wrong-secret"), jwt.Claims{
		"sub": "u",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id_token":"` + idToken + `"}`))
	}))
	defer token.Close()

	s := New(Config{ClientID: "cid", TokenURL: token.URL, JWKSecret: secret, HTTPClient: token.Client()}, nil)

	r := httptest.NewRequest(http.MethodGet, "/cb?code=x", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}
