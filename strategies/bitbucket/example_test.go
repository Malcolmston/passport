package bitbucket_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/bitbucket"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full backend wiring for the Bitbucket OAuth2 strategy. It
// registers the strategy with passport, supplying the client credentials and
// the callback URL along with a verify func that maps the fetched Bitbucket
// profile to your application user. The "/auth/bitbucket" route carries no ?code=
// parameter, so Authenticate redirects the browser to Bitbucket's authorization
// page to begin the flow. Bitbucket then redirects back to "/auth/bitbucket/callback"
// with a code, which the strategy exchanges for an access token before fetching
// the profile and running verify. On success the wrapped handler runs and sends
// the user home, whereas returning a nil user from verify rejects the login.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(bitbucket.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/bitbucket/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/bitbucket", p.Authenticate("bitbucket")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/bitbucket/callback", p.Authenticate("bitbucket")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend serves the browser-facing page that starts the Bitbucket login
// flow. It is a minimal HTML document containing a single "Sign in with Bitbucket"
// link that points at the "/auth/bitbucket" initiation route wired in ExampleNew.
// When the visitor clicks the link the browser navigates to that route, where
// the strategy redirects on to Bitbucket's consent screen. After the user approves
// and Bitbucket calls back, the backend establishes the session, so this page only
// needs to offer the entry point. In a real application you would render this
// markup as part of your sign-in page.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/bitbucket">Sign in with Bitbucket</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
