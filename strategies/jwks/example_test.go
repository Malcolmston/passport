package jwks_test

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwks"
)

// ExampleNew shows the full wiring for the JWKS strategy. The strategy is
// registered with passport under its name "jwks" and configured to fetch and
// cache the provider's signing keys from a JWKS endpoint. Tokens are verified
// against those rotating public keys, restricted to RS256 by the Algorithms
// allow-list, with the Issuer and Audience pinned to the provider and your
// application. The verify func maps the verified claims to your user — here the
// "sub" claim — and returning nil would reject the token. A single route is
// protected: by default the strategy reads the JWT from the "Authorization:
// Bearer" header, and only after successful verification does the protected
// handler run.
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

// Example_frontend shows the browser side that matches where this strategy
// reads the credential. By default the jwks strategy expects the token in the
// "Authorization: Bearer <jwt>" request header, so the script obtains a
// provider-issued JWT and sends it via fetch with that header. The token itself
// would normally come from an OpenID Connect sign-in flow; here it is a
// placeholder to keep the example self-contained. The request targets /api/me,
// the same route the strategy protects on the server, so the bearer token flows
// straight into verification against the provider's published key set. The
// login page is served from a local ServeMux only to make this a runnable,
// self-contained example.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
  <pre id="out"></pre>
  <script>
    // In production this comes from your OpenID Connect sign-in flow.
    var token = "PROVIDER_ISSUED_JWT";
    fetch("/api/me", {
      headers: {"Authorization": "Bearer " + token}
    }).then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
  </script>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
