package openidconnect_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/openidconnect"
)

// ExampleNew shows the full wiring for the OpenID Connect strategy: register it
// with passport, then mount the login and provider-callback routes. With no
// ?code= the strategy redirects the browser to the provider; the provider
// redirects back to the callback with a code that is exchanged for an id_token.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the verified id_token claims
	// to your application user (return a nil user to reject the login).
	p.Use(openidconnect.New(
		openidconnect.Config{
			Issuer:       "https://idp.example.com",
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "https://app.example.com/auth/openidconnect/callback",
			AuthURL:      "https://idp.example.com/authorize",
			TokenURL:     "https://idp.example.com/token",
			JWKSURL:      "https://idp.example.com/.well-known/jwks.json",
			Scopes:       []string{"profile", "email"},
		},
		func(claims jwt.Claims) (user any, err error) {
			return claims.Subject(), nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/openidconnect", p.Authenticate("openidconnect")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/openidconnect/callback", p.Authenticate("openidconnect")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
