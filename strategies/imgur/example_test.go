package imgur_test

import (
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/imgur"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full wiring for the Imgur OAuth2 strategy. First the
// strategy is registered with passport via p.Use, passing the client
// credentials, the callback URL, and a verify function. The verify function
// maps the fetched oauth2.Profile to your application's user value and rejects
// the login by returning a nil user (with a nil error). The /auth/imgur route
// begins the flow by redirecting the browser to Imgur's authorization page, and
// the /auth/imgur/callback route completes it after Imgur redirects back with
// an authorization code. In the browser, a user clicks a "Sign in with Imgur"
// link pointing at /auth/imgur, authorizes the app on Imgur, and is returned to
// the callback route where the success handler runs.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(imgur.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/imgur/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/imgur", p.Authenticate("imgur")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/imgur/callback", p.Authenticate("imgur")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of the Imgur login flow. The front
// end does not talk OAuth itself; it is just an anchor pointing at the server's
// /auth/imgur route. When the user clicks the link, the server redirects the
// browser to Imgur, where the user authorizes the application. Imgur then sends
// the browser back to the /auth/imgur/callback route, which finishes the
// exchange and establishes the session. The page below is the entire
// client-side contribution to authentication.
func Example_frontend() {
	const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/imgur">Sign in with Imgur</a>
  </body>
</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
