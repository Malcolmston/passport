package mixcloud_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/mixcloud"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the Mixcloud OAuth2 strategy.
// It registers the strategy with passport under the name "mixcloud", supplying
// the client credentials, the callback URL, and a verify function that maps the
// result to your application user. The /auth/mixcloud route begins login by
// redirecting the browser to Mixcloud; with no ?code= present the strategy issues
// that redirect. Mixcloud then redirects back to /auth/mixcloud/callback with a
// code, which the strategy exchanges for an access token before running verify.
// Because Mixcloud has no userinfo endpoint here, identify the user from
// Profile.AccessToken inside verify; on success the callback handler runs and the
// user is established in the session.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(mixcloud.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/mixcloud/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/mixcloud", p.Authenticate("mixcloud")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/mixcloud/callback", p.Authenticate("mixcloud")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of Mixcloud login. It serves a page
// containing a single "Sign in with Mixcloud" link that points at the
// application's /auth/mixcloud route. When the visitor clicks it, the passport
// Authenticate handler mounted on that route redirects the browser onward to
// Mixcloud's consent screen. After the user approves, Mixcloud redirects back to
// the callback route wired in ExampleNew, which completes the login. This handler
// renders only the entry-point link; the OAuth redirect dance itself is handled
// server-side by the strategy.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/mixcloud">Sign in with Mixcloud</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
