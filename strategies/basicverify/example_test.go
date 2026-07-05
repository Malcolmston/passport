package basicverify_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/basicverify"
)

// ExampleNew shows the full wiring for the basicverify strategy: HTTP Basic
// authentication (RFC 7617) driven by a verify function. Register the strategy
// with a realm and verify func, then guard a route with it. Browsers present a
// native username/password prompt for a Basic challenge, so no custom login form
// is needed. The strategy registers under the name "basic-verify".
//
// A client authenticates by sending the credentials in the Authorization
// header (curl encodes "user:pass" for you):
//
//	curl -u alice:s3cret http://localhost:3000/private
func ExampleNew() {
	p := passport.New()

	// The verify func receives the decoded username/password and returns the
	// authenticated user. Return a nil user to reject with a 401 challenge.
	p.Use(basicverify.New(basicverify.Options{
		Realm: "Restricted",
		Verify: func(username, password string) (user any, err error) {
			if username == "alice" && password == "s3cret" {
				return username, nil
			}
			return nil, nil
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Basic is stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("basic-verify", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend serves the browser side of the basicverify strategy. Like
// plain Basic auth the credentials must ride in the Authorization header, so the
// page uses fetch() and constructs "Basic " + btoa("user:pass") to call the
// "/private" route wired in ExampleNew. If verification fails the server returns a
// 401 with a WWW-Authenticate: Basic realm="Restricted" header, which is the realm
// configured on the backend and what a browser would display in its native
// prompt. The credentials are inlined only to keep the example self-contained; a
// real page would gather them from a form. The fetch result is written into the
// page so the outcome is visible.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Basic verify demo</title></head>
<body>
  <pre id="out">loading...</pre>
  <script>
    fetch("/private", { headers: { "Authorization": "Basic " + btoa("alice:s3cret") } })
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
