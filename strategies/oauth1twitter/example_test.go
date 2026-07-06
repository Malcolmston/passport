package oauth1twitter_test

import (
	"log"
	"net/http"
	"net/url"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth1twitter"
)

// ExampleNew shows the full server-side wiring for the Twitter OAuth 1.0a
// strategy: register it with passport, then mount the login and callback routes.
// The strategy registers under the name "twitter" and is configured only with
// your Twitter application consumer key and secret and the callback URL, since
// the endpoints are preset by the package. The /auth/twitter route begins login;
// with no oauth_verifier present the strategy fetches a request token and
// redirects the browser to Twitter's authorize page. Twitter redirects back to
// /auth/twitter/callback with the verifier, which the strategy exchanges for an
// access token before running verify. On success the callback handler runs and
// the user is established in the session.
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

// Example_frontend shows the browser side of "Sign in with Twitter". It serves a
// page with a single "Sign in with Twitter" link that points at the application's
// /auth/twitter route. When the visitor clicks it, the passport Authenticate
// handler mounted on that route obtains a request token and redirects the browser
// onward to Twitter's authorization page. After the user approves, Twitter
// redirects back to the callback route wired in ExampleNew, which completes the
// login. This handler renders only the entry-point link; the OAuth 1.0a
// request-token dance is handled server-side by the strategy.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/twitter">Sign in with Twitter</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
