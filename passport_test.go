package passport_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

type user struct {
	ID   string
	Name string
}

// buildApp wires a small application: a login endpoint, a protected endpoint,
// and a logout endpoint, using the local strategy and session persistence.
func buildApp() (*passport.Passport, http.Handler) {
	users := map[string]user{"1": {ID: "1", Name: "Ada"}}

	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return users["1"], nil
		}
		return nil, local.ErrInvalidCredentials
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })
	p.DeserializeUser(func(id string, r *http.Request) (any, error) {
		if u, ok := users[id]; ok {
			return u, nil
		}
		return nil, nil
	})

	mux := http.NewServeMux()

	// Login: run the authenticate middleware in front of a success handler.
	loginSuccess := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := passport.User(r).(user)
		w.Write([]byte("welcome " + u.Name))
	})
	mux.Handle("/login", p.Authenticate("local")(loginSuccess))

	// Protected route.
	profile := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("profile: " + passport.User(r).(user).Name))
	})
	mux.Handle("/profile", p.RequireLogin("")(profile))

	// Logout.
	mux.Handle("/logout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.LogOut(w, r)
		w.Write([]byte("bye"))
	}))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	return p, handler
}

func TestLoginSuccessAndSession(t *testing.T) {
	_, app := buildApp()

	// 1. Log in.
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if w.Code != 200 || !strings.Contains(w.Body.String(), "welcome Ada") {
		t.Fatalf("login failed: code=%d body=%q", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatal("expected a session cookie to be set")
	}

	// 2. Use the session cookie to hit a protected route.
	r2 := httptest.NewRequest("GET", "/profile", nil)
	for _, c := range cookie {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	app.ServeHTTP(w2, r2)
	if w2.Code != 200 || !strings.Contains(w2.Body.String(), "profile: Ada") {
		t.Fatalf("protected route failed: code=%d body=%q", w2.Code, w2.Body.String())
	}
}

func TestLoginFailure(t *testing.T) {
	_, app := buildApp()
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestProtectedRouteRequiresAuth(t *testing.T) {
	_, app := buildApp()
	r := httptest.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", w.Code)
	}
}

func TestLogout(t *testing.T) {
	_, app := buildApp()

	// Log in first.
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	cookies := w.Result().Cookies()

	// Log out.
	r2 := httptest.NewRequest("POST", "/logout", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	app.ServeHTTP(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("logout code=%d", w2.Code)
	}

	// The old cookie should no longer grant access.
	r3 := httptest.NewRequest("GET", "/profile", nil)
	for _, c := range cookies {
		r3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()
	app.ServeHTTP(w3, r3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", w3.Code)
	}
}

func TestJSONLogin(t *testing.T) {
	_, app := buildApp()
	r := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"ada","password":"secret"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "welcome Ada") {
		t.Fatalf("json login failed: code=%d body=%q", w.Code, w.Body.String())
	}
}

func TestStatelessAuthenticate(t *testing.T) {
	users := map[string]string{"token123": "svc"}
	p := passport.New()
	p.UseNamed("token", &tokenStrategy{tokens: users})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi " + passport.User(r).(string)))
	})
	// Session disabled: no cookie, purely per-request.
	h := p.Authenticate("token", passport.Options{Session: false})(protected)
	app := passport.Chain(h, p.Initialize())

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token123")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "hi svc" {
		t.Fatalf("stateless auth failed: code=%d body=%q", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("stateless auth should not set a session cookie")
	}
}

// tokenStrategy is a tiny bearer-token strategy used to exercise custom
// strategies and stateless authentication.
type tokenStrategy struct{ tokens map[string]string }

func (t *tokenStrategy) Name() string { return "token" }
func (t *tokenStrategy) Authenticate(c *passport.Context, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if name, ok := t.tokens[token]; ok {
		c.Success(name)
		return
	}
	c.Fail("invalid token", http.StatusUnauthorized)
}
