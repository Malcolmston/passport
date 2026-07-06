package oauth1_test

import (
	"log"
	"net/http"
	"net/url"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth1"
)

// ExampleNew shows the full server-side wiring for the generic OAuth 1.0a
// strategy, the shared base that provider wrappers such as oauth1twitter build
// on. It registers the strategy with passport under the name "oauth1", supplying
// the consumer key and secret, the three provider endpoints, the callback URL,
// and a verify function that maps the granted access token and token parameters
// to your application user. The /auth/oauth1 route begins login; with no
// oauth_verifier present the strategy fetches a request token and redirects the
// browser to the provider's authorize page. The provider redirects back to
// /auth/oauth1/callback with the verifier, which the strategy exchanges for an
// access token before running verify. On success the callback handler runs and
// the user is established in the session.
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

// Example_frontend shows the browser side of the generic OAuth 1.0a login. It
// serves a page with a single "Sign in" button (an anchor) that points at the
// application's /auth/oauth1 route. When the visitor clicks it, the passport
// Authenticate handler mounted on that route obtains a request token and
// redirects the browser onward to the provider's authorization page. After the
// user approves, the provider redirects back to the callback route wired in
// ExampleNew, which completes the login. This handler renders only the generic
// entry-point button; the OAuth 1.0a request-token dance is handled server-side
// by the strategy.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/oauth1">Sign in</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
