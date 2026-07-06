package anonymous_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/anonymous"
)

// ExampleNew shows the full wiring for the anonymous strategy: register it with
// passport, then mount it on a route. The anonymous strategy always declines to
// handle the request (it "passes"), so Authenticate lets the request through
// unauthenticated instead of returning 401. This makes it useful as a fallback
// on routes that should work for both logged-in and guest visitors: the handler
// checks passport.User to see whether anyone is signed in.
func ExampleNew() {
	p := passport.New()

	// Register the anonymous strategy. It never fails; it simply passes.
	p.Use(anonymous.New())

	// The handler runs whether or not a user is authenticated.
	greet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := passport.User(r); u != nil {
			_, _ = fmt.Fprintf(w, "hello, %v", u)
			return
		}
		_, _ = fmt.Fprint(w, "hello, guest")
	})

	mux := http.NewServeMux()
	// Because anonymous passes, the request always reaches greet.
	mux.Handle("/", p.Authenticate("anonymous")(greet))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
