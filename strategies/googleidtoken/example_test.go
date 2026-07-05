package googleidtoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/googleidtoken"
)

// ExampleNew shows the full wiring for verifying a Google Sign-In id_token
// presented directly by the client: register the strategy with passport and
// mount a protected route that consumes the credential.
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
