package bearertoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/bearertoken"
)

// ExampleNew shows the full wiring for opaque bearer-token authentication via
// token introspection: register the strategy with passport, then guard a route
// with it. The token is read from the "Authorization: Bearer <token>" header
// and handed to the Verify func, which introspects it (e.g. against a token
// store or an introspection endpoint).
//
// The strategy registers under the name "bearer-token" (its Name()), so that is
// the name passed to Authenticate.
//
// A client authenticates by presenting the token in the Authorization header:
//
//	curl -H "Authorization: Bearer t0k3n-abc123" http://localhost:3000/private
func ExampleNew() {
	p := passport.New()

	// The verify func introspects the opaque token and returns the user. Return
	// bearertoken.ErrInvalidToken (or a nil user) to reject the token.
	p.Use(bearertoken.New(func(token string) (user any, err error) {
		if token == "t0k3n-abc123" {
			return "service-account", nil
		}
		return nil, bearertoken.ErrInvalidToken
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Bearer tokens are stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("bearer-token", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
