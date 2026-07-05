package gitea_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/gitea"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full wiring for the Gitea OAuth2 strategy: register it
// with passport, then mount the login and provider-callback routes.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile to your
	// application user (return a nil user to reject the login).
	p.Use(gitea.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/gitea/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/gitea", p.Authenticate("gitea")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/gitea/callback", p.Authenticate("gitea")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
