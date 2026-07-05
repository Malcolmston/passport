package googleidtoken_test

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/googleidtoken"
)

// ExampleNew shows the full wiring for verifying a Google Sign-In id_token
// presented directly by the client. The strategy is registered with passport
// under its name "google-id-token" and configured to verify RS256 tokens
// against Google's rotating public keys published at GoogleCertsURL. The
// Audience is pinned to your OAuth client id and the Issuer to Google's, so a
// validly signed token minted for a different application is rejected. A single
// route is protected: the strategy reads the credential from the "id_token"
// query parameter or POST form field, verifies its signature and expiry, and on
// success makes the token claims the authenticated user. Finally the passport
// middleware is installed for every request with passport.Chain before the
// server starts serving.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. In production, verify RS256 id_tokens against
	// Google's rotating public keys and pin the audience to your client id.
	p.Use(googleidtoken.New(googleidtoken.Options{
		JWKSURL:  googleidtoken.GoogleCertsURL,
		Audience: "YOUR_CLIENT_ID.apps.googleusercontent.com",
		Issuer:   "https://accounts.google.com",
	}))

	// A route protected by the "google-id-token" strategy. On success the
	// id_token claims become the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "signed in: %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The client posts the credential from Google Sign-In as "id_token":
	//   curl -d "id_token=<jwt>" https://app.example.com/auth/google
	mux.Handle("/auth/google", p.Authenticate("google-id-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side that matches where this strategy
// reads the credential. Google Sign-In hands the page a signed id_token (the
// "credential" in the Google Identity Services callback), which the script
// posts to the backend as an application/x-www-form-urlencoded body of the form
// "id_token=<jwt>". That "id_token" form field is exactly what the strategy
// reads on the server, so the credential flows straight into verification. The
// login page below is served from a local ServeMux purely to keep the example
// self-contained; in production the same HTML would be your sign-in page and
// /auth/google would be the route protected by the "google-id-token" strategy.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
  <!-- Google Sign-In renders its button here (script loaded in production). -->
  <div id="g_id_signin"
       data-client_id="YOUR_CLIENT_ID.apps.googleusercontent.com"
       data-callback="onCredential"></div>
  <script>
    // Google Identity Services calls this with the signed id_token credential.
    function onCredential(resp) {
      fetch("/auth/google", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: "id_token=" + encodeURIComponent(resp.credential)
      }).then(function (r) { return r.text(); })
        .then(function (t) { document.body.append(t); });
    }
  </script>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
