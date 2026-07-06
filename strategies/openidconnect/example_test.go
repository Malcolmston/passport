package openidconnect_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/openidconnect"
)

// ExampleNew shows the full wiring for the OpenID Connect strategy. It registers
// the strategy with passport and then mounts the two routes the flow needs. With
// no ?code= the first route redirects the browser to the provider's
// authorization endpoint, and the provider redirects back to the callback route
// with a code that is exchanged for an id_token. Because Config.JWKSURL is set,
// the returned id_token is verified against the provider's published RS256/ES256
// signing keys, and Config.Issuer pins the accepted "iss" claim. The verify func
// maps the verified id_token claims to your application user, and returning a nil
// user rejects the login.
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

// Example_frontend shows the browser side of an OpenID Connect login. A real
// application renders a page with a "Sign in with OpenID Connect" link that
// points at the server's /auth/openidconnect route. Clicking it hands the
// browser to passport, which issues the 302 redirect to the provider's
// authorization endpoint with a scope that includes "openid". After the user
// authenticates at the identity provider, it redirects back to the
// /auth/openidconnect/callback route wired in ExampleNew, where the id_token is
// verified. No client-side JavaScript is required for the redirect flow.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OIDC redirect. -->
    <a href="/auth/openidconnect">Sign in with OpenID Connect</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
