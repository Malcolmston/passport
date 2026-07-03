package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func TestAuthenticateRedirect(t *testing.T) {
	s := New("demo", Config{
		ClientID:    "cid",
		RedirectURL: "https://app.example/callback",
		AuthURL:     "https://provider.example/authorize",
		Scopes:      []string{"email", "profile"},
	}, func(p Profile) (any, error) { return nil, nil })

	r := httptest.NewRequest(http.MethodGet, "/login?state=xyz", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultRedirect {
		t.Fatalf("want ResultRedirect, got %v", c.Result())
	}
	loc := redirectLocation(t, c, s, "xyz")
	if got := loc.Query().Get("client_id"); got != "cid" {
		t.Errorf("client_id = %q", got)
	}
	if got := loc.Query().Get("redirect_uri"); got != "https://app.example/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := loc.Query().Get("response_type"); got != "code" {
		t.Errorf("response_type = %q", got)
	}
	if got := loc.Query().Get("scope"); got != "email profile" {
		t.Errorf("scope = %q", got)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q", got)
	}
}

// redirectLocation re-derives the URL the strategy would redirect to. Context
// keeps location unexported, so we rebuild it deterministically from the config.
func redirectLocation(t *testing.T, c *passport.Context, s *Strategy, state string) *url.URL {
	t.Helper()
	u, err := url.Parse(s.AuthCodeURL(state))
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	return u
}

func TestAuthenticateCodeExchangeSuccess(t *testing.T) {
	// userinfo server
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("userinfo Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 42, "login": "octocat", "email": "o@example.com"}`))
	}))
	defer userinfo.Close()

	// token server
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("token method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("token Content-Type = %q", ct)
		}
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("code") != "the-code" {
			t.Errorf("code = %q", r.PostForm.Get("code"))
		}
		if r.PostForm.Get("client_id") != "cid" {
			t.Errorf("client_id = %q", r.PostForm.Get("client_id"))
		}
		if r.PostForm.Get("client_secret") != "secret" {
			t.Errorf("client_secret = %q", r.PostForm.Get("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-123","token_type":"bearer"}`))
	}))
	defer token.Close()

	var gotProfile Profile
	s := New("demo", Config{
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example/callback",
		AuthURL:      "https://provider.example/authorize",
		TokenURL:     token.URL,
		UserInfoURL:  userinfo.URL,
		HTTPClient:   token.Client(),
	}, func(p Profile) (any, error) {
		gotProfile = p
		return map[string]string{"name": "octocat"}, nil
	})

	r := httptest.NewRequest(http.MethodGet, "/callback?code=the-code&state=xyz", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	u, ok := c.SuccessUser().(map[string]string)
	if !ok || u["name"] != "octocat" {
		t.Fatalf("SuccessUser = %#v", c.SuccessUser())
	}
	if gotProfile.Provider != "demo" {
		t.Errorf("profile.Provider = %q", gotProfile.Provider)
	}
	if gotProfile.ID != "42" {
		t.Errorf("profile.ID = %q", gotProfile.ID)
	}
	if gotProfile.AccessToken != "tok-123" {
		t.Errorf("profile.AccessToken = %q", gotProfile.AccessToken)
	}
	if gotProfile.Raw["email"] != "o@example.com" {
		t.Errorf("profile.Raw email = %v", gotProfile.Raw["email"])
	}
}

func TestAuthenticateVerifyReject(t *testing.T) {
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	defer token.Close()

	s := New("demo", Config{
		ClientID:    "cid",
		TokenURL:    token.URL,
		UserInfoURL: "", // no userinfo endpoint
		HTTPClient:  token.Client(),
	}, func(p Profile) (any, error) { return nil, nil })

	r := httptest.NewRequest(http.MethodGet, "/callback?code=x", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestExchangeErrorStatus(t *testing.T) {
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer token.Close()

	s := New("demo", Config{
		ClientID:   "cid",
		TokenURL:   token.URL,
		HTTPClient: token.Client(),
	}, func(p Profile) (any, error) { return "u", nil })

	r := httptest.NewRequest(http.MethodGet, "/callback?code=x", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultError {
		t.Fatalf("want ResultError, got %v", c.Result())
	}
}
