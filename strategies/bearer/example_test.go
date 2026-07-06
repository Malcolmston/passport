package bearer_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/bearer"
)

// ExampleNew shows the full backend wiring for HTTP Bearer token authentication
// (RFC 6750). It registers the strategy with a VerifyFunc that resolves a
// presented token to a user, then mounts it on "/private" with
// passport.Options{Session: false} because bearer tokens are stateless. On each
// request the token is taken from the "Authorization: Bearer <token>" header, the
// access_token query parameter, or the access_token form field, and only a
// successful Verify lets the protected handler run. Returning bearer.ErrInvalidToken
// (or a nil user) rejects the request with an invalid_token challenge. A client
// authenticates by presenting the token:
//
//	curl -H "Authorization: Bearer t0k3n-abc123" http://localhost:3000/private
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

// Example_frontend serves the HTML+JavaScript page a browser client uses to call
// a bearer-protected endpoint. The page runs fetch() against the "/private" route
// wired in ExampleNew, sending the token in the "Authorization: Bearer <token>"
// header — the primary location RFC 6750 defines and the one this strategy checks
// first. The strategy also accepts the token as an access_token query parameter,
// shown as a comment for clients that cannot set headers, though the header is
// preferred because query values leak into logs. The token is inlined only for
// the example; a real single-page app stores it after a login exchange. The
// response text is written into the page so the result is visible.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Bearer token demo</title></head>
<body>
  <pre id="out">loading...</pre>
  <script>
    fetch("/private", { headers: { "Authorization": "Bearer t0k3n-abc123" } })
      .then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
    // Or via the query parameter:
    //   fetch("/private?access_token=t0k3n-abc123")
  </script>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
