package discord_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/discord"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the Discord OAuth2 strategy.
// It registers the strategy with a passport instance, supplying a verify func
// that maps the fetched provider profile to your application's user (returning a
// nil user rejects the login). It then mounts two routes: an initiation route
// that redirects the browser to Discord's authorization endpoint, and a callback
// route that Discord redirects back to with an authorization code. On the
// callback the strategy exchanges the code for an access token, fetches the
// user's profile, and runs the verify func before the success handler runs.
// Finally it wraps the mux with passport's Initialize and Session middleware so
// the authenticated user is persisted across requests.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(discord.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/discord/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/discord", p.Authenticate("discord")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/discord/callback", p.Authenticate("discord")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser-facing half of the Discord login flow. It
// serves a minimal HTML login page whose only interactive element is a "Sign in
// with Discord" anchor pointing at the /auth/discord initiation route wired up in
// ExampleNew. The browser never sees the client secret or handles tokens:
// clicking the link simply navigates to your server, which issues the OAuth2
// redirect to Discord. After the user authorizes the application, Discord returns
// them to the callback route and the session is established. Serve this page from
// any public, unauthenticated route such as your site's login screen.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/discord">Sign in with Discord</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
