package openidconnect

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// tokenServerFor returns a stub token endpoint that hands back idToken.
func tokenServerFor(idToken string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"` + idToken + `"}`))
	}))
}

func mustSign(t *testing.T, key []byte, claims jwt.Claims) string {
	t.Helper()
	tok, err := jwt.Sign(key, claims)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return tok
}

// TestAudienceIsEnforced pins OpenID Connect Core Section 3.1.3.7 step 3. An
// id_token the provider minted for a different relying party must not
// authenticate here, or a token leaked from (or issued to) another client of
// the same IdP could be replayed against this one.
func TestAudienceIsEnforced(t *testing.T) {
	cases := []struct {
		name  string
		aud   any
		allow bool
	}{
		{"exact match", "cid", true},
		{"present in array", []any{"other", "cid"}, true},
		{"different client", "someone-else", false},
		{"array without us", []any{"a", "b"}, false},
		{"missing audience", nil, false},
		{"wrong type", 42, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.Claims{
				"iss": "https://idp.example",
				"sub": "user-123",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			}
			if tt.aud != nil {
				claims["aud"] = tt.aud
			}
			srv := tokenServerFor(mustSign(t, secret, claims))
			defer srv.Close()

			s := New(Config{
				Issuer:    "https://idp.example",
				ClientID:  "cid",
				TokenURL:  srv.URL,
				JWKSecret: secret,
				// The stub token endpoint speaks plain HTTP.
				HTTPClient: srv.Client(),
			}, nil)

			r := httptest.NewRequest(http.MethodGet, "/cb?code=the-code", nil)
			c := &passport.Context{}
			s.Authenticate(c, r)

			want := passport.ResultFail
			if tt.allow {
				want = passport.ResultSuccess
			}
			if c.Result() != want {
				t.Errorf("Result() = %v, want %v (err %v)", c.Result(), want, c.Err())
			}
		})
	}
}

// TestNoVerificationKeyFailsClosed covers the misconfiguration where neither a
// JWKS endpoint nor a shared secret is supplied. The HS256 fallback would
// otherwise verify every id_token against a zero-length HMAC key, which anyone
// can reproduce — so the strategy must refuse rather than accept forgeries.
func TestNoVerificationKeyFailsClosed(t *testing.T) {
	// Signed with an empty key: exactly what an attacker who knows the
	// strategy is misconfigured would produce.
	forged := mustSign(t, nil, jwt.Claims{
		"iss": "https://idp.example",
		"sub": "attacker",
		"aud": "cid",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	srv := tokenServerFor(forged)
	defer srv.Close()

	s := New(Config{
		ClientID:   "cid",
		TokenURL:   srv.URL,
		HTTPClient: srv.Client(),
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/cb?code=the-code", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() == passport.ResultSuccess {
		t.Fatal("a strategy with no verification key must never authenticate")
	}

	if _, err := s.verifyIDToken(forged); !errors.Is(err, ErrNoVerificationKey) {
		t.Errorf("verifyIDToken error = %v, want ErrNoVerificationKey", err)
	}
}
