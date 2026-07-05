package oauth1_test

import (
	"log"
	"net/http"
	"net/url"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth1"
)

// ExampleNew shows the full wiring for the generic OAuth 1.0a strategy: register
// it with passport, then mount the login and provider-callback routes. With no
// oauth_verifier the strategy obtains a request token and redirects the browser
// to the provider; the provider redirects back to the callback with the
// verifier, which is exchanged for an access token.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the granted access token (and
	// the raw token-endpoint parameters) to your application user (return a nil
	// user to reject the login).
	p.Use(oauth1.New(
		"oauth1",
		oauth1.Config{
			ConsumerKey:     "CONSUMER_KEY",
			ConsumerSecret:  "CONSUMER_SECRET",
			RequestTokenURL: "https://provider.example.com/oauth/request_token",
			AuthorizeURL:    "https://provider.example.com/oauth/authorize",
			AccessTokenURL:  "https://provider.example.com/oauth/access_token",
			CallbackURL:     "https://app.example.com/auth/oauth1/callback",
		},
		func(accessToken, accessSecret string, params url.Values) (user any, err error) {
			return params.Get("user_id"), nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/oauth1", p.Authenticate("oauth1")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/oauth1/callback", p.Authenticate("oauth1")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
