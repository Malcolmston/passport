package sessionjwt_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/sessionjwt"
)

// ExampleNew shows the full wiring for the stateless session JWT strategy. It
// registers the strategy with passport and mounts two routes. The /login route
// stands in for a primary login: it mints a session JWT with Issue and writes it
// as a cookie with SetCookie. The /dashboard route is protected by the
// "session-jwt" strategy, so it runs only when a valid session cookie is present,
// and the cookie's claims become the authenticated user. The browser sends the
// session cookie automatically on every request, so no header or body is needed.
func ExampleNew() {
	strategy := sessionjwt.New(sessionjwt.Options{
		Secret: []byte("session-signing-secret"),
	})

	p := passport.New()
	p.Use(strategy)

	// After a primary login, mint a session JWT and write it as a cookie.
	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := strategy.Issue(jwt.Claims{"sub": "user-123"}, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		strategy.SetCookie(w, token)
	})

	// A route protected by the "session-jwt" strategy. It runs only when a
	// valid session cookie is present; the cookie's claims become the user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	// The browser sends the session cookie automatically:
	//   curl --cookie "session=<jwt>" https://app.example.com/dashboard
	mux.Handle("/dashboard", p.Authenticate("session-jwt")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of a stateless JWT session. The
// session JWT lives in an HttpOnly cookie set by the server at login, so
// JavaScript never touches it and the browser attaches it automatically. The
// login form below posts credentials to /login, where the server issues the
// cookie. Afterward, fetching a protected route like /dashboard with
// credentials included sends the cookie so the request is authenticated. Because
// the credential is a cookie, the client needs no Authorization header.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Sign in</button>
    </form>
    <script>
      // The HttpOnly session cookie is sent automatically for same-origin
      // requests; credentials:"include" also covers cross-origin fetches.
      async function loadDashboard() {
        const res = await fetch("/dashboard", { credentials: "include" });
        if (!res.ok) { window.location = "/"; }
      }
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
