package line_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/line"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the LINE OAuth2 strategy. It
// registers the strategy with passport under the name "line", supplying the
// client credentials, the callback URL, and a verify function that maps the
// fetched profile to your application user. The /auth/line route begins login by
// redirecting the browser to LINE; with no ?code= present the strategy issues
// that redirect. LINE then redirects back to /auth/line/callback with a code,
// which the strategy exchanges for an access token and uses to fetch the profile
// before running verify. On success the callback handler runs and the user is
// established in the session.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(line.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/line/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/line", p.Authenticate("line")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/line/callback", p.Authenticate("line")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of LINE login. It serves a page
// containing a single "Sign in with LINE" link that points at the application's
// /auth/line route. When the visitor clicks it, the passport Authenticate handler
// mounted on that route redirects the browser onward to LINE's consent screen.
// After the user approves, LINE redirects back to the callback route wired in
// ExampleNew, which completes the login. This handler renders only the entry-point
// link; the OAuth redirect dance itself is handled server-side by the strategy.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/line">Sign in with LINE</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
