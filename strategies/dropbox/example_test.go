package dropbox_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/dropbox"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the Dropbox OAuth2 strategy.
// It registers the strategy with a passport instance, supplying a verify func
// that maps the fetched provider profile to your application's user (returning a
// nil user rejects the login). It then mounts two routes: an initiation route
// that redirects the browser to Dropbox's authorization endpoint, and a callback
// route that Dropbox redirects back to with an authorization code. On the
// callback the strategy exchanges the code for an access token and attempts to
// fetch the current account before running the verify func. Finally it wraps the
// mux with passport's Initialize and Session middleware so the authenticated user
// is persisted across requests.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. Dropbox returns the identifier as account_id in the
	// raw map; return a nil user to reject the login.
	p.Use(dropbox.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/dropbox/callback",
		func(profile oauth2.Profile) (user any, err error) {
			if id, ok := profile.Raw["account_id"].(string); ok {
				return id, nil
			}
			return profile.AccessToken, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/dropbox", p.Authenticate("dropbox")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/dropbox/callback", p.Authenticate("dropbox")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser-facing half of the Dropbox login flow. It
// serves a minimal HTML login page whose only interactive element is a "Sign in
// with Dropbox" anchor pointing at the /auth/dropbox initiation route wired up in
// ExampleNew. The browser never sees the client secret or handles tokens:
// clicking the link simply navigates to your server, which issues the OAuth2
// redirect to Dropbox. After the user authorizes the application, Dropbox returns
// them to the callback route and the session is established. Serve this page from
// any public, unauthenticated route such as your site's login screen.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/dropbox">Sign in with Dropbox</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
