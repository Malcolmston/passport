package custom_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/custom"
)

// ExampleNew shows the full wiring for the custom strategy: register an
// arbitrary AuthFunc under a name of your choice, then guard a route with it.
// The AuthFunc inspects the raw *http.Request and returns the authenticated
// user, a nil user to reject with 401, or an error for an internal failure.
// This is the escape hatch for authentication schemes that no built-in strategy
// covers.
func ExampleNew() {
	p := passport.New()

	// A trivial AuthFunc that authenticates on a shared secret header.
	p.Use(custom.New("apikey-header", func(r *http.Request) (user any, err error) {
		if r.Header.Get("X-API-Key") == "s3cret" {
			return "service-account", nil
		}
		return nil, nil // nil user -> 401
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The custom strategy is registered under the name passed to New.
	mux.Handle("/api", p.Authenticate("apikey-header", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
