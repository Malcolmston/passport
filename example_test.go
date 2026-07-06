package passport_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

// account is the application's user model for the examples below.
type account struct {
	ID   string
	Name string
}

// ExampleNew shows an end-to-end backend: it registers a strategy, defines the
// serialize/deserialize functions that bridge a user and the session, and wires
// Initialize, Session, and Authenticate onto a net/http mux. The /login route is
// guarded by Authenticate("local"), which runs the local strategy's credential
// check and, on success, establishes the login session and redirects home. The
// /me route is protected by RequireLogin, which lets the request through only
// when Session has restored an authenticated user, readable with passport.User.
// Chain installs the middleware outermost-first, so Initialize runs before
// Session before the routes. This is the canonical shape of a passport
// application and mirrors the wiring of a Passport.js Express app.
func ExampleNew() {
	users := map[string]account{"1": {ID: "1", Name: "Ada"}}

	p := passport.New()

	// Register a strategy. Any strategy under strategies/ plugs in the same way.
	p.Use(local.New(func(username, password string) (any, error) {
		if username == "ada" && password == "secret" {
			return users["1"], nil
		}
		return nil, local.ErrInvalidCredentials
	}))

	// Bridge the user object and the session id stored in the cookie.
	p.SerializeUser(func(u any) (string, error) { return u.(account).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		if u, ok := users[id]; ok {
			return u, nil
		}
		return nil, nil
	})

	mux := http.NewServeMux()

	// Login endpoint: POST username/password, redirect home on success.
	mux.Handle("/login", p.Authenticate("local", passport.Options{
		SuccessRedirect: "/me",
		FailureRedirect: "/login?error=1",
	})(nil))

	// Logout endpoint clears the session.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = p.LogOut(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Protected endpoint: only reachable when authenticated.
	mux.Handle("/me", p.RequireLogin("/login")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello %s", passport.User(r).(account).Name)
		}),
	))

	// Install passport for every request, then serve.
	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend renders the canonical passport login landing page. Passport
// is a backend library and serves no UI of its own, so the front end is just
// HTML that points the browser at the routes you registered. A local
// username/password strategy is a form that POSTs to the /login route guarded by
// Authenticate; each OAuth provider strategy is a "Sign in with X" link to that
// provider's login route, which issues the redirect to the provider. The page
// below combines both: a credential form plus a list of provider links, exactly
// as a real multi-strategy sign-in screen would. Which links you show should
// match the strategies you registered with Use on the server.
func Example_frontend() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in</title>
<h1>Sign in</h1>

<form method="post" action="/login">
  <label>Username <input name="username" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>

<p>Or use a provider:</p>
<ul>
  <li><a href="/auth/slack">Sign in with Slack</a></li>
  <li><a href="/auth/spotify">Sign in with Spotify</a></li>
  <li><a href="/auth/twitch">Sign in with Twitch</a></li>
</ul>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
