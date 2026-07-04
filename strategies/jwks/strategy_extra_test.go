package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

func jwkFor(kid string, key *rsa.PrivateKey) JWK {
	return JWK{
		Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
		N: b64.EncodeToString(key.PublicKey.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func futureClaims() Claims {
	return Claims{"sub": "u", "exp": float64(time.Now().Add(time.Hour).Unix())}
}

func TestStrategyName(t *testing.T) {
	if New(Options{Set: &Set{}}, nil).Name() != "jwks" {
		t.Fatal("name")
	}
}

func TestStrategyMissingToken(t *testing.T) {
	s := New(Options{Set: &Set{}}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestStrategyAudienceMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{jwkFor("s1", key)}}
	claims := futureClaims()
	claims["aud"] = "other"
	tok := signRS256(t, key, "s1", claims)
	s := New(Options{Set: set, Audience: "wanted"}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestStrategyVerifyFuncError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{jwkFor("s1", key)}}
	tok := signRS256(t, key, "s1", futureClaims())
	boom := errors.New("lookup failed")
	s := New(Options{Set: set}, func(c Claims) (any, error) { return nil, boom })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError || c.Err() != boom {
		t.Fatalf("result=%v err=%v", c.Result(), c.Err())
	}
}

func TestStrategyVerifyFuncNilUser(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{jwkFor("s1", key)}}
	tok := signRS256(t, key, "s1", futureClaims())
	s := New(Options{Set: set}, func(c Claims) (any, error) { return nil, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestStrategyCustomResolve(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signRS256(t, key, "custom", futureClaims())
	called := false
	s := New(Options{Resolve: func(kid, alg string) (any, error) {
		called = true
		if kid != "custom" || alg != "RS256" {
			t.Fatalf("resolve got kid=%q alg=%q", kid, alg)
		}
		return &key.PublicKey, nil
	}}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || !called {
		t.Fatalf("result=%v called=%v", c.Result(), called)
	}
}

func TestVerifyToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{jwkFor("s1", key)}}
	tok := signRS256(t, key, "s1", futureClaims())
	s := New(Options{Set: set}, nil)
	claims, err := s.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject() != "u" {
		t.Fatalf("sub=%q", claims.Subject())
	}
}

func TestExtractTokenFromParam(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := &Set{Keys: []JWK{jwkFor("s1", key)}}
	tok := signRS256(t, key, "s1", futureClaims())

	// id_token query param.
	s := New(Options{Set: set, TokenFromParam: true}, nil)
	r := httptest.NewRequest(http.MethodGet, "/?id_token="+tok, nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("id_token query: %v (%v)", c.Result(), c.Err())
	}

	// access_token query param.
	r = httptest.NewRequest(http.MethodGet, "/?access_token="+tok, nil)
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("access_token query: %v", c.Result())
	}

	// id_token form field.
	form := url.Values{"id_token": {tok}}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("id_token form: %v", c.Result())
	}

	// access_token form field.
	form = url.Values{"access_token": {tok}}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("access_token form: %v", c.Result())
	}

	// No token anywhere → fail.
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("no param token: %v", c.Result())
	}
}

func TestKeyFromEndpointEmptyURL(t *testing.T) {
	// No JWKSURL, no Set, no Resolve → resolver falls to keyFromEndpoint → ErrKey.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signRS256(t, key, "s1", futureClaims())
	s := New(Options{}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestFetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signRS256(t, key, "s1", futureClaims())
	s := New(Options{JWKSURL: srv.URL}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail on 500, got %v", c.Result())
	}
}

func TestKeyRotationRefetch(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	var mu sync.Mutex
	active := jwkFor("kid-1", key1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(Set{Keys: []JWK{active}})
	}))
	defer srv.Close()

	s := New(Options{JWKSURL: srv.URL}, nil)

	// First request with kid-1 populates the cache.
	tok1 := signRS256(t, key1, "kid-1", futureClaims())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok1)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("first request: %v (%v)", c.Result(), c.Err())
	}

	// Rotate the server's key. Cache is fresh but the kid is unknown → refetch.
	mu.Lock()
	active = jwkFor("kid-2", key2)
	mu.Unlock()
	tok2 := signRS256(t, key2, "kid-2", futureClaims())
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok2)
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("rotated request: %v (%v)", c.Result(), c.Err())
	}
}

func TestServeStaleOnFetchError(t *testing.T) {
	key, srv := makeRSAJWKS(t, "kid-1")
	// Force every lookup to treat the cache as stale so a refetch is attempted.
	s := New(Options{JWKSURL: srv.URL, CacheTTL: time.Nanosecond}, nil)

	tok := signRS256(t, key, "kid-1", futureClaims())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("prime cache: %v (%v)", c.Result(), c.Err())
	}

	// Server gone: the refetch fails but the stale cached key still serves.
	srv.Close()
	time.Sleep(2 * time.Millisecond)
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("stale serve: %v (%v)", c.Result(), c.Err())
	}
}
