package apitoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/apitoken"
)

// ExampleNew shows the full wiring for opaque API-token authentication:
// register the strategy with passport, then guard a route with it. The token is
// read from the Authorization header ("Bearer <t>" or "Token <t>") or from the
// configured header (here "X-API-Token").
//
// The strategy registers under the name "api-token" (its Name()), so that is
// the name passed to Authenticate.
//
// A client authenticates by presenting the token:
//
//	curl -H "Authorization: Bearer t0k3n-abc123" http://localhost:3000/private
//	curl -H "X-API-Token: t0k3n-abc123"          http://localhost:3000/private
func ExampleNew() {
	p := passport.New()

	// Lookup resolves a presented token to a user; ok is false for unknown or
	// revoked tokens. (For a single static token, set Options.Token/User
	// instead, which are compared in constant time.)
	p.Use(apitoken.New(apitoken.Options{
		Header: "X-API-Token",
		Lookup: func(token string) (user any, ok bool) {
			if apitoken.ConstantTimeEqual(token, "t0k3n-abc123") {
				return "service-account", true
			}
			return nil, false
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Tokens are stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("api-token", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
