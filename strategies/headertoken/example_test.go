package headertoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/headertoken"
)

// ExampleNew shows the full wiring for the headertoken strategy: register it
// with passport, then mount a route protected by the token check.
//
// A client supplies the token in the configured request header (here
// "X-Auth-Token"):
//
//	curl -H "X-Auth-Token: s3cr3t-token" https://app.example.com/api/me
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The Verify func maps a raw token to your
	// application user; return a nil user (or headertoken.ErrInvalidToken) to
	// reject the request.
	p.Use(headertoken.New(headertoken.Options{
		Header: "X-Auth-Token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, headertoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	// A protected handler that reads the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "header-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("header-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
