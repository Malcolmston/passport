package apikey_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/apikey"
)

// ExampleNew shows the full wiring for API-key authentication: register the
// strategy with passport, then guard a route with it. The key is read from the
// configured header (here "X-API-Key") and, as a fallback, from the "api_key"
// query parameter.
//
// A client authenticates by presenting the key in the header:
//
//	curl -H "X-API-Key: k3y-abc123" http://localhost:3000/private
//
// or via the query parameter:
//
//	curl "http://localhost:3000/private?api_key=k3y-abc123"
func ExampleNew() {
	p := passport.New()

	// Verify resolves a presented key to a user. Return apikey.ErrInvalidKey
	// (or a nil user) to reject an unknown or revoked key.
	p.Use(apikey.New(apikey.Options{
		Header: "X-API-Key",
		Query:  "api_key",
		Verify: func(key string) (user any, err error) {
			if key == "k3y-abc123" {
				return "service-account", nil
			}
			return nil, apikey.ErrInvalidKey
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// API keys are stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("apikey", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
