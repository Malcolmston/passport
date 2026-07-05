package bearertoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/bearertoken"
)

// ExampleNew shows the full backend wiring for opaque bearer-token authentication
// via token introspection. It registers the strategy with a VerifyFunc that
// introspects the token — here a trivial comparison, but in practice a lookup
// against a token store or an RFC 7662 introspection endpoint — and returns the
// user. The strategy registers under the name "bearer-token" (its Name()), so
// that is the name passed to Authenticate, and it is mounted with
// passport.Options{Session: false} because tokens are stateless. The token is
// read only from the "Authorization: Bearer <token>" header, and only a
// successful introspection lets the protected handler run. A client authenticates
// by presenting the token:
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

// Example_frontend serves the HTML+JavaScript page a browser client uses to call
// a bearertoken-protected endpoint. The page runs fetch() against the "/private"
// route wired in ExampleNew, sending the token in the "Authorization: Bearer
// <token>" header — the only place this strategy reads it, since bearertoken
// deliberately ignores the query string and form body. The token is embedded in
// client script only to keep the example self-contained; a real single-page app
// obtains it from a login exchange and keeps it in memory. The fetch result is
// written into the page so the outcome is visible. This is the exact browser side
// that matches the header-only backend.
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
