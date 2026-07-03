package passport_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

// buildCallbackApp wires a Passport with the local strategy and a login route
// driven by AuthenticateCallback.
func buildCallbackApp(cb func(w http.ResponseWriter, r *http.Request, err error, user any, info any)) http.Handler {
	users := map[string]user{"1": {ID: "1", Name: "Ada"}}

	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return users["1"], nil
		}
		return nil, local.ErrInvalidCredentials
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })

	mux := http.NewServeMux()
	mux.Handle("/login", p.AuthenticateCallback("local", cb))
	return passport.Chain(mux, p.Initialize())
}

func TestAuthenticateCallbackSuccess(t *testing.T) {
	var gotUser any
	var gotErr error
	app := buildCallbackApp(func(w http.ResponseWriter, r *http.Request, err error, u any, info any) {
		gotUser = u
		gotErr = err
		if u == nil {
			http.Error(w, "no user", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("welcome " + u.(user).Name))
	})

	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if gotErr != nil {
		t.Fatalf("unexpected err: %v", gotErr)
	}
	if u, ok := gotUser.(user); !ok || u.Name != "Ada" {
		t.Fatalf("expected Ada user, got %#v", gotUser)
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "welcome Ada") {
		t.Fatalf("callback success: code=%d body=%q", w.Code, w.Body.String())
	}
}

func TestAuthenticateCallbackFailure(t *testing.T) {
	var gotUser any
	var gotInfo any
	var gotErr error
	app := buildCallbackApp(func(w http.ResponseWriter, r *http.Request, err error, u any, info any) {
		gotUser = u
		gotInfo = info
		gotErr = err
		http.Error(w, "denied", http.StatusForbidden)
	})

	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if gotErr != nil {
		t.Fatalf("failure should carry nil err, got %v", gotErr)
	}
	if gotUser != nil {
		t.Fatalf("failure should carry nil user, got %v", gotUser)
	}
	m, ok := gotInfo.(map[string]any)
	if !ok {
		t.Fatalf("expected info map, got %#v", gotInfo)
	}
	if m["message"] != "Invalid credentials" {
		t.Fatalf("expected challenge message, got %v", m["message"])
	}
	if m["status"] != http.StatusUnauthorized {
		t.Fatalf("expected status 401 in info, got %v", m["status"])
	}
	// The app fully controls the response here.
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected app-controlled 403, got %d", w.Code)
	}
}

func TestAuthenticateCallbackUnknownStrategy(t *testing.T) {
	p := passport.New()
	var gotErr error
	h := passport.Chain(p.AuthenticateCallback("nope", func(w http.ResponseWriter, r *http.Request, err error, u any, info any) {
		gotErr = err
	}), p.Initialize())

	r := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if gotErr == nil {
		t.Fatal("expected an error for unknown strategy")
	}
}

func TestAuthenticateCallbackLogIn(t *testing.T) {
	// cb calls p.LogIn on success; a session cookie should be set.
	users := map[string]user{"1": {ID: "1", Name: "Ada"}}
	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return users["1"], nil
		}
		return nil, local.ErrInvalidCredentials
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })

	handler := p.AuthenticateCallback("local", func(w http.ResponseWriter, r *http.Request, err error, u any, info any) {
		if u == nil {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if err := p.LogIn(w, r, u); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ok"))
	})
	app := passport.Chain(handler, p.Initialize())

	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("expected LogIn to set a session cookie")
	}
}

func TestAuthenticateAnyFirstFailsSecondSucceeds(t *testing.T) {
	users := map[string]user{"1": {ID: "1", Name: "Ada"}}
	p := passport.New()
	// "local" fails (wrong password); "token" succeeds.
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return users["1"], nil
		}
		return nil, local.ErrInvalidCredentials
	}))
	p.UseNamed("token", &tokenStrategy{tokens: map[string]string{"t": "svc"}})
	p.SerializeUser(func(u any) (string, error) {
		switch v := u.(type) {
		case user:
			return v.ID, nil
		case string:
			return v, nil
		}
		return "", nil
	})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi " + passport.User(r).(string)))
	})
	h := p.AuthenticateAny([]string{"local", "token"})(protected)
	app := passport.Chain(h, p.Initialize())

	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=ada&password=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer t")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if w.Code != 200 || w.Body.String() != "hi svc" {
		t.Fatalf("AuthenticateAny: code=%d body=%q", w.Code, w.Body.String())
	}
}

func TestAuthenticateAnyAllFail(t *testing.T) {
	p := passport.New()
	p.UseNamed("token", &tokenStrategy{tokens: map[string]string{"good": "svc"}})
	p.UseNamed("token2", &tokenStrategy{tokens: map[string]string{"alsogood": "svc2"}})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach"))
	})
	h := p.AuthenticateAny([]string{"token", "token2"})(protected)
	app := passport.Chain(h, p.Initialize())

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer bad")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when all strategies fail, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "invalid token" {
		t.Fatalf("expected challenge from last strategy, got %q", w.Header().Get("WWW-Authenticate"))
	}
}
