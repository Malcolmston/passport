package passport_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

// recordingStore wraps a Store so tests can observe which session ids were
// written and destroyed.
type recordingStore struct {
	inner     passport.Store
	destroyed []string
	written   []string
}

func newRecordingStore() *recordingStore {
	return &recordingStore{inner: passport.NewMemoryStore()}
}

func (s *recordingStore) Get(id string) (map[string]any, bool) { return s.inner.Get(id) }

func (s *recordingStore) Set(id string, data map[string]any) {
	s.written = append(s.written, id)
	s.inner.Set(id, data)
}

func (s *recordingStore) Destroy(id string) {
	s.destroyed = append(s.destroyed, id)
	s.inner.Destroy(id)
}

// sessionApp builds a minimal app whose /login endpoint authenticates with the
// local strategy and whose /whoami endpoint reports the current user.
func sessionApp(t *testing.T, configure func(*passport.Passport)) (*passport.Passport, http.Handler) {
	t.Helper()

	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return user{ID: "1", Name: "Ada"}, nil
		}
		return nil, local.ErrInvalidCredentials
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		if id == "1" {
			return user{ID: "1", Name: "Ada"}, nil
		}
		return nil, nil
	})
	if configure != nil {
		configure(p)
	}

	mux := http.NewServeMux()
	mux.Handle("/login", p.Authenticate("local")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })))
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		if !passport.IsAuthenticated(r) {
			w.Write([]byte("anonymous"))
			return
		}
		w.Write([]byte(passport.User(r).(user).Name))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := p.LogOut(w, r); err != nil {
			t.Errorf("LogOut: %v", err)
		}
		w.Write([]byte("bye"))
	})

	return p, passport.Chain(mux, p.Initialize(), p.Session())
}

func postLogin(h http.Handler, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"username": {"ada"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// sessionCookie returns the session cookie a browser would end up holding after
// this response: when a response carries several Set-Cookie headers of the same
// name, the last one wins.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == passport.DefaultCookieName {
			found = c
		}
	}
	return found
}

// TestLogInRotatesSessionID is the session-fixation guard. An attacker who can
// plant a known session id in a victim's browser (via a subdomain, an injected
// Set-Cookie, or a URL parameter in some stacks) must not end up holding a
// valid id once the victim authenticates. LogIn therefore issues a brand new id
// and destroys the old one, so the pre-login id is worthless afterwards.
func TestLogInRotatesSessionID(t *testing.T) {
	store := newRecordingStore()
	_, h := sessionApp(t, func(p *passport.Passport) { p.SetStore(store) })

	// Establish a session, then log in from within it.
	first := postLogin(h)
	preLogin := sessionCookie(t, first)
	if preLogin == nil {
		t.Fatal("first login set no session cookie")
	}

	second := postLogin(h, preLogin)
	postLoginCookie := sessionCookie(t, second)
	if postLoginCookie == nil {
		t.Fatal("second login set no session cookie")
	}

	if postLoginCookie.Value == preLogin.Value {
		t.Errorf("session id was not rotated on login: still %q (session fixation)", preLogin.Value)
	}

	// The superseded id must be gone from the store, not merely unreferenced.
	var destroyed bool
	for _, id := range store.destroyed {
		if id == preLogin.Value {
			destroyed = true
		}
	}
	if !destroyed {
		t.Errorf("pre-login session id %q was not destroyed on rotation", preLogin.Value)
	}
	if _, ok := store.Get(preLogin.Value); ok {
		t.Errorf("pre-login session id %q is still resolvable after login", preLogin.Value)
	}
}

// TestAttackerSuppliedCookieIsNotAdopted checks that a session id the server
// never issued does not become the session id: load() must fall back to a fresh
// session rather than trusting the client's value.
func TestAttackerSuppliedCookieIsNotAdopted(t *testing.T) {
	_, h := sessionApp(t, nil)

	planted := &http.Cookie{Name: passport.DefaultCookieName, Value: "attacker-chosen-id"}
	rec := postLogin(h, planted)

	got := sessionCookie(t, rec)
	if got == nil {
		t.Fatal("login set no session cookie")
	}
	if got.Value == planted.Value {
		t.Error("server adopted the client-supplied session id (session fixation)")
	}

	// And the planted id must not authenticate anything.
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.AddCookie(planted)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if body := rec2.Body.String(); body != "anonymous" {
		t.Errorf("planted cookie authenticated as %q, want anonymous", body)
	}
}

// TestLogOutDestroysSessionAndCookie verifies that logout is complete: the
// server-side record is destroyed, the cookie is expired, and replaying the old
// cookie does not restore the user.
func TestLogOutDestroysSessionAndCookie(t *testing.T) {
	store := newRecordingStore()
	_, h := sessionApp(t, func(p *passport.Passport) { p.SetStore(store) })

	loginRec := postLogin(h)
	authed := sessionCookie(t, loginRec)
	if authed == nil {
		t.Fatal("login set no session cookie")
	}

	// Sanity: the session works before logout.
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.AddCookie(authed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.String() != "Ada" {
		t.Fatalf("pre-logout /whoami = %q, want Ada", rec.Body.String())
	}

	// Log out.
	req = httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(authed)
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, req)

	cleared := sessionCookie(t, logoutRec)
	if cleared == nil {
		t.Fatal("logout did not send a Set-Cookie to clear the session")
	}
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("logout cookie = %q MaxAge=%d, want empty value and negative MaxAge", cleared.Value, cleared.MaxAge)
	}
	if _, ok := store.Get(authed.Value); ok {
		t.Error("session data survived logout in the store")
	}

	// Replaying the pre-logout cookie must not resurrect the login.
	req = httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.AddCookie(authed)
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, req)
	if body := replay.Body.String(); body != "anonymous" {
		t.Errorf("replayed pre-logout cookie authenticated as %q, want anonymous", body)
	}
}

// TestLogOutThenTouchSessionDoesNotResurrect pins the hardening applied to
// destroy(), which used to leave the session id and dirty flag in place. No
// current code path reached a save() after LogOut without an intervening
// regenerate(), so this was a latent footgun rather than a live bug — but any
// future caller that flushed the session post-logout would have written the
// cleared data back under the destroyed id and re-issued the cookie logout had
// just expired. This test locks the invariant in before that happens.
func TestLogOutThenTouchSessionDoesNotResurrect(t *testing.T) {
	store := newRecordingStore()

	p := passport.New()
	p.SetStore(store)
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		return user{ID: "1", Name: "Ada"}, nil
	})

	// A handler that logs in, immediately logs out, then logs in again — the
	// worst case for stale session state within one request.
	h := passport.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := p.LogIn(w, r, user{ID: "1", Name: "Ada"}); err != nil {
			t.Fatalf("LogIn: %v", err)
		}
		if err := p.LogOut(w, r); err != nil {
			t.Fatalf("LogOut: %v", err)
		}
		if err := p.LogIn(w, r, user{ID: "1", Name: "Ada"}); err != nil {
			t.Fatalf("second LogIn: %v", err)
		}
		if !passport.IsAuthenticated(r) {
			t.Error("expected the request to be authenticated after the second LogIn")
		}
	}), p.Initialize(), p.Session())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// A resurrected session shows up either as a write to an id after that id
	// was destroyed, or as a destroyed id still resolving in the store.
	for _, id := range store.destroyed {
		if laterWrite(store, id) {
			t.Errorf("session id %q was written back after being destroyed", id)
		}
		if _, ok := store.Get(id); ok {
			t.Errorf("destroyed session id %q is still resolvable", id)
		}
	}

	// The surviving cookie must name a live session, not a destroyed one.
	final := sessionCookie(t, rec)
	if final == nil {
		t.Fatal("no session cookie after the final LogIn")
	}
	if _, ok := store.Get(final.Value); !ok {
		t.Errorf("final cookie %q does not resolve to a stored session", final.Value)
	}
}

// laterWrite reports whether id was written after its last destroy.
func laterWrite(s *recordingStore, id string) bool {
	lastDestroy, lastWrite := -1, -1
	for i, d := range s.destroyed {
		if d == id {
			lastDestroy = i
		}
	}
	for i, w := range s.written {
		if w == id {
			lastWrite = i
		}
	}
	return lastWrite > lastDestroy
}

// TestSetStorePreservesCookieSettings is a regression test for a configuration
// bug: SetStore rebuilt the session manager from scratch, silently discarding
// the Secure flag (and SameSite) set by an earlier SecureCookies call. A
// deployment that configured cookie security before swapping in a Redis store
// would ship session cookies over plain HTTP without any warning.
func TestSetStorePreservesCookieSettings(t *testing.T) {
	for _, order := range []string{"secure-then-store", "store-then-secure"} {
		t.Run(order, func(t *testing.T) {
			_, h := sessionApp(t, func(p *passport.Passport) {
				if order == "secure-then-store" {
					p.SecureCookies(true).SameSite(http.SameSiteStrictMode).CookieName("app.sid")
					p.SetStore(passport.NewMemoryStore())
				} else {
					p.SetStore(passport.NewMemoryStore())
					p.SecureCookies(true).SameSite(http.SameSiteStrictMode).CookieName("app.sid")
				}
			})

			rec := postLogin(h)
			var c *http.Cookie
			for _, got := range (&http.Response{Header: rec.Header()}).Cookies() {
				if got.Name == "app.sid" {
					c = got
				}
			}
			if c == nil {
				t.Fatalf("no app.sid cookie set; got headers %v", rec.Header())
			}
			if !c.Secure {
				t.Error("Secure flag was lost")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("SameSite = %v, want Strict", c.SameSite)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly flag was lost")
			}
		})
	}
}

// TestDefaultCookieIsHardened pins the out-of-the-box cookie attributes.
func TestDefaultCookieIsHardened(t *testing.T) {
	_, h := sessionApp(t, nil)
	c := sessionCookie(t, postLogin(h))
	if c == nil {
		t.Fatal("no session cookie")
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly so script cannot read it")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax by default", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if len(c.Value) < 32 {
		t.Errorf("session id %q is only %d chars; want a high-entropy value", c.Value, len(c.Value))
	}
}

// TestCookieNameIgnoresEmpty confirms the setter refuses a name that would make
// the cookie unreadable.
func TestCookieNameIgnoresEmpty(t *testing.T) {
	_, h := sessionApp(t, func(p *passport.Passport) { p.CookieName("") })
	if c := sessionCookie(t, postLogin(h)); c == nil {
		t.Error("empty CookieName should have left the default name in place")
	}
}

// TestFailedAuthDoesNotReachHandler is the fall-through guard: when a strategy
// fails, the wrapped handler must never run and the response must not be a
// success.
func TestFailedAuthDoesNotReachHandler(t *testing.T) {
	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		return nil, local.ErrInvalidCredentials
	}))
	p.SerializeUser(func(u any) (string, error) { return "1", nil })

	reached := false
	h := passport.Chain(
		p.Authenticate("local")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.Write([]byte("SHOULD NOT HAPPEN"))
		})),
		p.Initialize(),
	)

	form := url.Values{"username": {"ada"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached {
		t.Error("failed authentication fell through to the protected handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if sessionCookie(t, rec) != nil {
		t.Error("a failed login must not establish a session cookie")
	}
}

// TestPassedAuthReachesHandlerUnauthenticated documents the deliberate
// difference: a strategy that *declines* (Pass) continues the chain, but does
// so without an authenticated user, so RequireLogin still blocks.
func TestPassedAuthReachesHandlerUnauthenticated(t *testing.T) {
	p := passport.New()
	p.UseNamed("declining", declineStrategy{})

	var authed bool
	reached := false
	h := passport.Chain(
		p.Authenticate("declining")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			authed = passport.IsAuthenticated(r)
		})),
		p.Initialize(),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !reached {
		t.Error("a declining strategy should continue the chain")
	}
	if authed {
		t.Error("a declining strategy must not leave the request authenticated")
	}
}

type declineStrategy struct{}

func (declineStrategy) Name() string { return "declining" }

func (declineStrategy) Authenticate(c *passport.Context, r *http.Request) { c.Pass() }

// TestStatelessAuthenticateSetsNoCookie confirms Options{Session: NoSession()}
// authenticates the request without persisting anything — the correct behaviour
// for token/API auth, where a stray session cookie would be a CSRF surface.
func TestStatelessAuthenticateSetsNoCookie(t *testing.T) {
	p := passport.New()
	p.Use(local.New(func(username, password string) (any, error) {
		return user{ID: "1", Name: "Ada"}, nil
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })

	var authed bool
	h := passport.Chain(
		p.Authenticate("local", passport.Options{Session: passport.NoSession()})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authed = passport.IsAuthenticated(r)
			})),
		p.Initialize(),
	)

	form := url.Values{"username": {"ada"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !authed {
		t.Error("stateless authentication should still authenticate the request")
	}
	if sessionCookie(t, rec) != nil {
		t.Error("Session:false must not set a session cookie")
	}
}

// TestLogInWithoutInitializeErrors pins the middleware-ordering contract: using
// LogIn without Initialize is an error, never a silent no-op that leaves the
// caller believing a session exists.
func TestLogInWithoutInitializeErrors(t *testing.T) {
	p := passport.New()
	p.SerializeUser(func(u any) (string, error) { return "1", nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	if err := p.LogIn(rec, req, user{ID: "1"}); err == nil {
		t.Error("LogIn without Initialize should return an error")
	}
	if err := p.LogOut(rec, req); err == nil {
		t.Error("LogOut without Initialize should return an error")
	}
	if passport.IsAuthenticated(req) {
		t.Error("a request with no passport state must not be authenticated")
	}
	if passport.User(req) != nil {
		t.Error("User on a request with no passport state should be nil")
	}
}
