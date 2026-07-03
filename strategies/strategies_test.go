// Package strategies_test exercises the bundled strategies through the full
// passport middleware stack.
package strategies_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/anonymous"
	"github.com/malcolmston/passport/strategies/basic"
	"github.com/malcolmston/passport/strategies/bearer"
	"github.com/malcolmston/passport/strategies/jwt"
)

func guardedApp(p *passport.Passport, name string, opts passport.Options) http.Handler {
	h := p.Authenticate(name, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("user:"))
		if u, ok := passport.User(r).(string); ok {
			w.Write([]byte(u))
		}
	}))
	return passport.Chain(h, p.Initialize())
}

func TestBearerStrategy(t *testing.T) {
	p := passport.New()
	p.Use(bearer.New(func(token string) (any, error) {
		if token == "good-token" {
			return "svc", nil
		}
		return nil, bearer.ErrInvalidToken
	}))
	app := guardedApp(p, "bearer", passport.Options{Session: false})

	// Valid token.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer good-token")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "user:svc" {
		t.Fatalf("bearer valid: code=%d body=%q", w.Code, w.Body.String())
	}

	// Missing/invalid token.
	w2 := httptest.NewRecorder()
	app.ServeHTTP(w2, httptest.NewRequest("GET", "/", nil))
	if w2.Code != 401 {
		t.Fatalf("bearer missing: expected 401, got %d", w2.Code)
	}
}

func TestBasicStrategy(t *testing.T) {
	p := passport.New()
	p.Use(basic.New(func(u, pw string) (any, error) {
		if u == "admin" && pw == "s3cret" {
			return "admin", nil
		}
		return nil, basic.ErrInvalidCredentials
	}))
	app := guardedApp(p, "basic", passport.Options{Session: false})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:s3cret")))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "user:admin" {
		t.Fatalf("basic valid: code=%d body=%q", w.Code, w.Body.String())
	}

	// Wrong password.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:nope")))
	w2 := httptest.NewRecorder()
	app.ServeHTTP(w2, r2)
	if w2.Code != 401 {
		t.Fatalf("basic wrong: expected 401, got %d", w2.Code)
	}
	if got := w2.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate challenge on basic failure")
	}
}

func TestJWTStrategy(t *testing.T) {
	secret := []byte("test-secret")
	p := passport.New()
	p.Use(jwt.New(secret, func(claims jwt.Claims) (any, error) {
		return claims.Subject(), nil
	}))
	app := guardedApp(p, "jwt", passport.Options{Session: false})

	// Valid, unexpired token.
	token, err := jwt.Sign(secret, jwt.Claims{
		"sub": "user-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "user:user-1" {
		t.Fatalf("jwt valid: code=%d body=%q", w.Code, w.Body.String())
	}

	// Expired token -> 401.
	expired, _ := jwt.Sign(secret, jwt.Claims{
		"sub": "user-1",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("Authorization", "Bearer "+expired)
	w2 := httptest.NewRecorder()
	app.ServeHTTP(w2, r2)
	if w2.Code != 401 {
		t.Fatalf("jwt expired: expected 401, got %d", w2.Code)
	}

	// Tampered signature -> 401.
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.Header.Set("Authorization", "Bearer "+token+"x")
	w3 := httptest.NewRecorder()
	app.ServeHTTP(w3, r3)
	if w3.Code != 401 {
		t.Fatalf("jwt tampered: expected 401, got %d", w3.Code)
	}
}

func TestJWTParseRejectsWrongSecret(t *testing.T) {
	token, _ := jwt.Sign([]byte("secret-a"), jwt.Claims{"sub": "x"})
	s := jwt.New([]byte("secret-b"), func(jwt.Claims) (any, error) { return "x", nil })
	if _, err := s.Parse(token); err == nil {
		t.Fatal("expected signature error with wrong secret")
	}
}

func TestAnonymousStrategyPasses(t *testing.T) {
	p := passport.New()
	p.Use(anonymous.New())
	// With Pass(), Authenticate falls through to the next handler unauthenticated.
	app := guardedApp(p, "anonymous", passport.Options{Session: false})
	w := httptest.NewRecorder()
	app.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || w.Body.String() != "user:" {
		t.Fatalf("anonymous: expected pass-through, code=%d body=%q", w.Code, w.Body.String())
	}
}
