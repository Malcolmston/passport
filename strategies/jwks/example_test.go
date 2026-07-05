package jwks_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwks"
)

// ExampleNew shows the full wiring for the JWKS strategy: verify RS256/ES256
// tokens against an OpenID Connect provider's published key set, register the
// strategy with passport, and mount a protected route.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. Keys are fetched from the provider's JWKS endpoint
	// and cached; the verify func maps the verified claims to your user.
	p.Use(jwks.New(jwks.Options{
		JWKSURL:    "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:     "https://accounts.google.com",
		Audience:   "YOUR_CLIENT_ID.apps.googleusercontent.com",
		Algorithms: []string{"RS256"},
	}, func(claims jwks.Claims) (user any, err error) {
		return claims.Subject(), nil
	}))

	// A route protected by the "jwks" strategy. It only runs after a valid
	// bearer token is verified against the JWKS.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// A client presents the provider-issued token:
	//   curl -H "Authorization: Bearer <jwt>" https://app.example.com/api/me
	mux.Handle("/api/me", p.Authenticate("jwks")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
