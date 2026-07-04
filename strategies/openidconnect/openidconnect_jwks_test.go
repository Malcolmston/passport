package openidconnect

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

var b64u = base64.RawURLEncoding

const cryptoHash = crypto.SHA256

// signRS256 issues an RS256-signed id_token.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	si := b64u.EncodeToString(hb) + "." + b64u.EncodeToString(cb)
	sum := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return si + "." + b64u.EncodeToString(sig)
}

// TestAuthenticateRS256ViaJWKS exercises the production path: the id_token is
// RS256-signed and verified against a JWKS endpoint, exactly as a real OIDC
// provider (Google/Auth0/Okta) works.
func TestAuthenticateRS256ViaJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "sign-1", "alg": "RS256", "use": "sig",
			"n": b64u.EncodeToString(key.PublicKey.N.Bytes()),
			"e": b64u.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}}
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer jwksSrv.Close()

	idToken := signRS256(t, key, "sign-1", jwt.Claims{
		"iss": "https://idp.example",
		"sub": "rs-user",
		"aud": "cid",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"` + idToken + `"}`))
	}))
	defer tokenSrv.Close()

	s := New(Config{
		Issuer:   "https://idp.example",
		ClientID: "cid",
		TokenURL: tokenSrv.URL,
		JWKSURL:  jwksSrv.URL,
	}, nil)

	r := httptest.NewRequest(http.MethodGet, "/cb?code=the-code", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(jwt.Claims)
	if claims.Subject() != "rs-user" {
		t.Errorf("sub = %q", claims.Subject())
	}
}

// TestAuthenticateRS256BadKey rejects a token signed by a different key.
func TestAuthenticateRS256BadKey(t *testing.T) {
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	evil, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "sign-1", "alg": "RS256",
			"n": b64u.EncodeToString(good.PublicKey.N.Bytes()),
			"e": b64u.EncodeToString(big.NewInt(int64(good.PublicKey.E)).Bytes()),
		}}}
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer jwksSrv.Close()

	idToken := signRS256(t, evil, "sign-1", jwt.Claims{
		"sub": "attacker", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id_token":"` + idToken + `"}`))
	}))
	defer tokenSrv.Close()

	s := New(Config{ClientID: "cid", TokenURL: tokenSrv.URL, JWKSURL: jwksSrv.URL}, nil)
	r := httptest.NewRequest(http.MethodGet, "/cb?code=x", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}
