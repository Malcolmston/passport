package oauth2_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full wiring for the generic OAuth2 authorization-code
// strategy: register it with passport, then mount the login and
// provider-callback routes. With no ?code= the strategy redirects the browser
// to the provider; the provider redirects back to the callback with a code that
// is exchanged for an access token and used to fetch the user's profile.
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
