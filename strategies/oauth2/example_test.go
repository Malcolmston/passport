package oauth2_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the generic OAuth2
// authorization-code strategy, the shared base the concrete provider packages
// build on. It registers the strategy with passport under the name "oauth2",
// supplying the client credentials, the provider's authorization, token, and
// userinfo URLs, the requested scopes, and a verify function that maps the
// fetched profile to your application user. The /auth/oauth2 route begins login
// by redirecting the browser to the provider; with no ?code= present the strategy
// issues that redirect. The provider redirects back to /auth/oauth2/callback with
// a code, which the strategy exchanges for an access token and uses to fetch the
// profile before running verify. On success the callback handler runs and the
// user is established in the session.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the fetched Profile to your
	// application user (return a nil user to reject the login).
	p.Use(oauth2.New(
		"oauth2",
		oauth2.Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "https://app.example.com/auth/oauth2/callback",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     "https://provider.example.com/token",
			UserInfoURL:  "https://provider.example.com/userinfo",
			Scopes:       []string{"profile", "email"},
		},
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/oauth2", p.Authenticate("oauth2")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/oauth2/callback", p.Authenticate("oauth2")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of the generic OAuth2 login. It serves
// a page with a single "Sign in" button (an anchor) that points at the
// application's /auth/oauth2 route. When the visitor clicks it, the passport
// Authenticate handler mounted on that route redirects the browser onward to the
// configured provider's authorization page. After the user approves, the provider
// redirects back to the callback route wired in ExampleNew, which completes the
// login. This handler renders only the generic entry-point button; the OAuth
// redirect dance itself is handled server-side by the strategy.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/oauth2">Sign in</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
