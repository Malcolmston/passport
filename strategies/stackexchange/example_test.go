package stackexchange_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth2"
	"github.com/malcolmston/passport/strategies/stackexchange"
)

// ExampleNew shows the full server-side wiring for the Stack Exchange OAuth 2.0
// strategy. It registers the strategy with passport and mounts two routes: a
// login route that begins the redirect to Stack Exchange, and a callback route that
// Stack Exchange returns to once the user has consented. The verify func maps the
// provider profile to your application user, and returning a nil user rejects
// the login. Authenticate performs the authorization-code exchange and, on
// success, establishes the login session before the callback handler runs.
// Finally Chain installs Initialize and Session so that every subsequent
// request can restore the logged-in user from the session cookie.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(stackexchange.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/stackexchange/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/stackexchange", p.Authenticate("stackexchange")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/stackexchange/callback", p.Authenticate("stackexchange")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend renders the browser-facing entry point for the Stack Exchange login
// flow. Passport never serves UI itself: the front end is simply an anchor that
// points at the /auth/stackexchange route wired up in ExampleNew. When the user clicks
// the link, the browser navigates to that route, which issues the 302 redirect
// on to Stack Exchange's consent screen. After the user approves access, the provider
// redirects back to the callback route and passport sets the session cookie.
// The handler below shows the minimal HTML needed to start the ceremony.
func Example_frontend() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in</title>
<a href="/auth/stackexchange">Sign in with Stack Exchange</a>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
