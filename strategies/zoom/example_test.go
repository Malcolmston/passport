package zoom_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth2"
	"github.com/malcolmston/passport/strategies/zoom"
)

// ExampleNew shows the full server-side wiring for the Zoom OAuth 2.0
// strategy. It registers the strategy with passport and mounts two routes: a
// login route that begins the redirect to Zoom, and a callback route that
// Zoom returns to once the user has consented. The verify func maps the
// provider profile to your application user, and returning a nil user rejects
// the login. Authenticate performs the authorization-code exchange and, on
// success, establishes the login session before the callback handler runs.
// Finally Chain installs Initialize and Session so that every subsequent
// request can restore the logged-in user from the session cookie.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(zoom.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/zoom/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/zoom", p.Authenticate("zoom")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/zoom/callback", p.Authenticate("zoom")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend renders the browser-facing entry point for the Zoom login
// flow. Passport never serves UI itself: the front end is simply an anchor that
// points at the /auth/zoom route wired up in ExampleNew. When the user clicks
// the link, the browser navigates to that route, which issues the 302 redirect
// on to Zoom's consent screen. After the user approves access, the provider
// redirects back to the callback route and passport sets the session cookie.
// The handler below shows the minimal HTML needed to start the ceremony.
func Example_frontend() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in</title>
<a href="/auth/zoom">Sign in with Zoom</a>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
