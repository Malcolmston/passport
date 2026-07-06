package reddit_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth2"
	"github.com/malcolmston/passport/strategies/reddit"
)

// ExampleNew shows the full wiring for the Reddit OAuth2 strategy. It registers
// the strategy with passport and then mounts the two routes the flow needs. The
// first route begins authorization by redirecting the browser to Reddit, and the
// second is the callback Reddit redirects back to with an authorization code.
// The verify func maps the fetched provider profile to your application user, and
// returning a nil user rejects the login. Finally the mux is wrapped with
// passport's Initialize and Session middleware so the authenticated user is
// available on later requests.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(reddit.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/reddit/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/reddit", p.Authenticate("reddit")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/reddit/callback", p.Authenticate("reddit")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of the Reddit login. A real
// application renders a page with a "Sign in with Reddit" link that points at
// the server's /auth/reddit route. Clicking it hands the browser to passport,
// which issues the 302 redirect to Reddit's authorization endpoint. After the
// user authorizes the app, Reddit redirects back to the /auth/reddit/callback
// route wired in ExampleNew. No client-side JavaScript is required for the
// redirect flow.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/reddit">Sign in with Reddit</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
