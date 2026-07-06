package bearer_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/bearer"
)

// ExampleNew shows the full wiring for HTTP Bearer token authentication
// (RFC 6750): register the strategy with passport, then guard a route with it.
// The token is taken from the Authorization header, the access_token query
// parameter, or the access_token form field.
//
// A client authenticates by presenting the token in the Authorization header:
//
//	curl -H "Authorization: Bearer t0k3n-abc123" http://localhost:3000/private
//
// or via the query parameter:
//
//	curl "http://localhost:3000/private?access_token=t0k3n-abc123"
func ExampleNew() {
	p := passport.New()

	// The verify func resolves a presented token to a user. Return
	// bearer.ErrInvalidToken (or a nil user) to reject an invalid token.
	p.Use(bearer.New(func(token string) (user any, err error) {
		if token == "t0k3n-abc123" {
			return "service-account", nil
		}
		return nil, bearer.ErrInvalidToken
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Bearer tokens are stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("bearer", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
