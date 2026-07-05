package jwtbearer_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwtbearer"
)

// ExampleNew shows the full wiring for the RFC 7523 JWT bearer grant: register
// the strategy with passport and mount a protected token endpoint. The client
// posts a signed JWT assertion in the "assertion" form field.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. Use Secret for HS256 assertions, or set JWKSURL to
	// verify RS256/ES256 assertions against the issuer's published keys.
	p.Use(jwtbearer.New(jwtbearer.Options{
		Secret: []byte("shared-assertion-secret"),
	}))

	// A route protected by the "jwt-bearer" strategy. On success the assertion
	// claims become the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "granted: %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Client POSTs grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer and
	// assertion=<jwt> as form fields:
	//   curl -d "assertion=<jwt>" https://app.example.com/oauth/token
	mux.Handle("/oauth/token", p.Authenticate("jwt-bearer")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
