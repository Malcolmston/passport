package custom_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/custom"
)

// ExampleNew shows the full wiring for the custom strategy: register an arbitrary
// AuthFunc under a name of your choice, then guard a route with it. The AuthFunc
// inspects the raw *http.Request and returns the authenticated user, a nil user to
// reject with HTTP 401, or an error for an internal failure. Here it authenticates
// on a shared-secret X-API-Key header, but the same pattern fits any check you can
// make from the request alone. The protected route is mounted with
// passport.Options{Session: false} because this API check is stateless. This is
// the escape hatch for authentication schemes that no built-in strategy covers.
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

// Example_frontend shows a browser frontend matched to the custom AuthFunc in
// ExampleNew, which authenticates on the X-API-Key header. Because the check reads
// a header rather than a cookie, a plain anchor will not do; instead the page uses
// a small script that issues a fetch and attaches the header explicitly. The
// browser therefore drives the protected request itself and prints the response.
// A real application would read the key from configuration or from the signed-in
// user's settings rather than hard-coding it. Tailor the fetch (or swap it for a
// form POST) to whatever your custom verify actually inspects.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Custom auth</title>
<script>
  // The AuthFunc authenticates on the X-API-Key header, so attach it to the
  // request to the protected route.
  fetch("/api", { headers: { "X-API-Key": "s3cret" } })
    .then(function (r) { return r.text(); })
    .then(console.log);
</script>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
