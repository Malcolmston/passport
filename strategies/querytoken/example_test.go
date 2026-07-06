package querytoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/querytoken"
)

// ExampleNew shows the full wiring for the querytoken strategy: register it
// with passport, then mount a route protected by the token check.
//
// A client supplies the token in the configured query parameter (here
// "token"):
//
//	curl "https://app.example.com/api/me?token=s3cr3t-token"
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The Verify func maps a raw token to your
	// application user; return a nil user (or querytoken.ErrInvalidToken) to
	// reject the request.
	p.Use(querytoken.New(querytoken.Options{
		Param: "token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, querytoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	// A protected handler that reads the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "query-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("query-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
