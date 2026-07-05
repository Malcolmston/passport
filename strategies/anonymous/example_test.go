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

// Example_frontend serves a public landing page for a route guarded by the
// anonymous strategy. Because the anonymous strategy lets unauthenticated
// requests through, the same page is served to signed-in users and guests alike,
// which is exactly the case anonymous is meant for. The page shows always-visible
// content and offers a "Log in" link to a real authentication route (such as an
// OAuth or local-login endpoint) for visitors who choose to sign in. The backend
// handler decides what to personalize by calling passport.User to see whether
// anyone is authenticated. This demonstrates the browser side of optional
// authentication: no gate, just an optional sign-in affordance.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Welcome</title></head>
<body>
  <h1>Public page</h1>
  <p>Everyone can read this, signed in or not.</p>
  <a href="/login">Log in</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
