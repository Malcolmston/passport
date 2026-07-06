package signedtoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/signedtoken"
)

// ExampleNew shows the full wiring for the signedtoken strategy: register it
// with passport, then mount a route protected by the signed-token check. The
// token is self-contained (HMAC-SHA256 signed JSON claims) and needs no
// server-side state.
//
// A client supplies the token in the Authorization header as a bearer token:
//
//	curl -H "Authorization: Bearer <base64url(claims)>.<hex(hmac)>" \
//	    https://app.example.com/api/me
func ExampleNew() {
	secret := []byte("super-secret-hmac-key")

	// Mint a signed token carrying the caller's claims (e.g. at login).
	token, err := signedtoken.Sign(secret, map[string]any{
		"sub":  "user-42",
		"role": "admin",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = token // hand this to the client; it presents it as a bearer token.

	p := passport.New()

	// Register the strategy. It verifies the signature (and any "exp" claim)
	// with the shared secret; the decoded claims become the authenticated user.
	p.Use(signedtoken.New(signedtoken.Options{
		Secret: secret,
	}))

	// A protected handler that reads the authenticated user (the claims map).
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := passport.User(r).(map[string]any)
		fmt.Fprintf(w, "hello %v", claims["sub"])
	})

	mux := http.NewServeMux()
	// The strategy name is "signed-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("signed-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
