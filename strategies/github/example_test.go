package github_test

import (
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/github"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the GitHub OAuth2 strategy.
// It registers the strategy with passport, supplying a verify func that maps the
// provider profile to your application user and rejects the login by returning a
// nil user. It mounts the /auth/github route, whose handler redirects the browser
// to GitHub to begin authorization. It also mounts the /auth/github/callback route,
// where GitHub redirects back with a code that the strategy exchanges before running
// verify and invoking the success handler. In the browser flow the user clicks a
// sign-in link, authorizes on GitHub, and is returned to the callback, at which
// point they are authenticated in the session.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(github.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/github/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/github", p.Authenticate("github")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/github/callback", p.Authenticate("github")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser/HTML side of the OAuth2 redirect flow. On the
// front end there is nothing to compute: sign-in is just an ordinary link that
// points at the server's /auth/github route. When the user clicks it, the
// server-side strategy redirects the browser to GitHub to authorize the app. After
// the user approves access, GitHub bounces the browser back to the application's
// callback route to finish authentication. Here the page is served by a local
// http.ServeMux purely so the example compiles and runs.
func Example_frontend() {
	const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/github">Sign in with GitHub</a>
  </body>
</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
