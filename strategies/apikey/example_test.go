package apikey_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/apikey"
)

// ExampleNew shows the full backend wiring for API-key authentication. It
// registers the strategy with passport, configuring the header ("X-API-Key"), a
// fallback query parameter ("api_key"), and a Verify func that resolves a
// presented key to a user. The strategy is then mounted on the "/private" route
// with passport.Options{Session: false}, because API keys are stateless and
// should not open a cookie session. On each request the key is read from the
// header (or the query parameter), and only a successful Verify lets the
// protected handler run. A client authenticates by presenting the key:
//
//	curl -H "X-API-Key: k3y-abc123" http://localhost:3000/private
//	curl "http://localhost:3000/private?api_key=k3y-abc123"
func ExampleNew() {
	p := passport.New()

	// Verify resolves a presented key to a user. Return apikey.ErrInvalidKey
	// (or a nil user) to reject an unknown or revoked key.
	p.Use(apikey.New(apikey.Options{
		Header: "X-API-Key",
		Query:  "api_key",
		Verify: func(key string) (user any, err error) {
			if key == "k3y-abc123" {
				return "service-account", nil
			}
			return nil, apikey.ErrInvalidKey
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// API keys are stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("apikey", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend serves the small HTML+JavaScript page a browser client uses
// to call an apikey-protected endpoint. The page runs a fetch() against the
// "/private" route wired in ExampleNew, sending the key in the "X-API-Key"
// request header — exactly where the strategy reads it. The key lives in client
// JavaScript here only to keep the example self-contained; in production an API
// key identifies a service and should be kept server-side rather than shipped to
// a browser. The strategy also accepts the key in the "api_key" query parameter,
// shown as a comment for callers that cannot set headers. Open the page and the
// fetch result is written into the page body.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>API key demo</title></head>
<body>
  <pre id="out">loading...</pre>
  <script>
    fetch("/private", { headers: { "X-API-Key": "k3y-abc123" } })
      .then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
    // Alternatively, without a custom header:
    //   fetch("/private?api_key=k3y-abc123")
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
