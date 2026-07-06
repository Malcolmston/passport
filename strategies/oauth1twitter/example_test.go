package oauth1twitter_test

import (
	"log"
	"net/http"
	"net/url"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth1twitter"
)

// ExampleNew shows the full wiring for the Twitter OAuth 1.0a strategy: register
// it with passport, then mount the login and provider-callback routes. The
// strategy registers under the name "twitter". With no oauth_verifier it
// redirects the browser to Twitter; Twitter redirects back to the callback with
// the verifier, which is exchanged for an access token.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the granted access token (and
	// the raw token-endpoint parameters) to your application user (return a nil
	// user to reject the login).
	p.Use(oauth1twitter.New(
		oauth1twitter.Config{
			ConsumerKey:    "CONSUMER_KEY",
			ConsumerSecret: "CONSUMER_SECRET",
			CallbackURL:    "https://app.example.com/auth/twitter/callback",
		},
		func(accessToken, accessSecret string, params url.Values) (user any, err error) {
			return params.Get("user_id"), nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to Twitter to begin authorization.
	mux.Handle("/auth/twitter", p.Authenticate("twitter")(nil))
	// Twitter redirects back here; the handler runs on success.
	mux.Handle("/auth/twitter/callback", p.Authenticate("twitter")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
