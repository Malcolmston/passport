package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

// makeRSAJWKS returns an RSA key and an httptest server publishing its public
// half as a JWKS document under the given kid.
func makeRSAJWKS(t *testing.T, kid string) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := Set{Keys: []JWK{{
		Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
		N: b64.EncodeToString(key.PublicKey.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(set)
	}))
	return key, srv
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	hb, _ := json.Marshal(header{Alg: "RS256", Kid: kid, Typ: "JWT"})
	cb, _ := json.Marshal(claims)
	si := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	h := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoSHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return si + "." + b64.EncodeToString(sig)
}

func TestStrategyEndpointSuccess(t *testing.T) {
	key, srv := makeRSAJWKS(t, "kid-1")
	defer srv.Close()

	tok := signRS256(t, key, "kid-1", Claims{
		"sub": "user-1", "iss": "https://issuer", "aud": "client-x",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	s := New(Options{JWKSURL: srv.URL, Issuer: "https://issuer", Audience: "client-x"}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want success, got %v (err=%v)", c.Result(), c.Err())
	}
	claims := c.SuccessUser().(map[string]any)
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v", claims["sub"])
	}
}

func TestStrategyWrongIssuer(t *testing.T) {
	key, srv := makeRSAJWKS(t, "kid-1")
	defer srv.Close()
	tok := signRS256(t, key, "kid-1", Claims{
		"iss": "https://evil", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	s := New(Options{JWKSURL: srv.URL, Issuer: "https://issuer"}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestStrategyRejectsHSKeyConfusion(t *testing.T) {
	// A token forged with HS256 using the (public) modulus as the secret must be
	// rejected — the resolver refuses HS* entirely.
	key, srv := makeRSAJWKS(t, "kid-1")
	defer srv.Close()
	_ = key
	// Build an HS256 token (signature won't matter; it must fail on alg).
	hb, _ := json.Marshal(header{Alg: "HS256", Kid: "kid-1"})
	cb, _ := json.Marshal(Claims{"sub": "attacker"})
	tok := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb) + ".AAAA"

	s := New(Options{JWKSURL: srv.URL}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("HS key-confusion token must fail, got %v", c.Result())
	}
}

func TestStrategyAlgorithmAllowList(t *testing.T) {
	key, srv := makeRSAJWKS(t, "kid-1")
	defer srv.Close()
	tok := signRS256(t, key, "kid-1", Claims{"sub": "u", "exp": float64(time.Now().Add(time.Hour).Unix())})

	// Only ES256 permitted → an RS256 token is rejected.
	s := New(Options{JWKSURL: srv.URL, Algorithms: []string{"ES256"}}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail for disallowed alg, got %v", c.Result())
	}
}

func TestStrategyStaticSet(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{{
		Kty: "RSA", Kid: "s1", Alg: "RS256",
		N: b64.EncodeToString(key.PublicKey.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	tok := signRS256(t, key, "s1", Claims{"sub": "static", "exp": float64(time.Now().Add(time.Hour).Unix())})

	s := New(Options{Set: set}, func(c Claims) (any, error) {
		return "user:" + c.Subject(), nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want success, got %v (err=%v)", c.Result(), c.Err())
	}
	if c.SuccessUser() != "user:static" {
		t.Fatalf("user = %v", c.SuccessUser())
	}
}
