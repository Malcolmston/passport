package basic_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/basic"
)

// ExampleNew shows the full backend wiring for HTTP Basic authentication
// (RFC 7617). It registers the strategy with a VerifyFunc that receives the
// decoded username and password and returns the authenticated user, then mounts
// it on "/private" with passport.Options{Session: false} because Basic sends
// credentials on every request. When the Authorization header is missing or
// verification fails, the strategy replies 401 with a Basic realm challenge, so
// browsers show their native credential prompt and no custom login form is
// required. Only a successful verification lets the protected handler run. A
// client authenticates by sending the credentials in the Authorization header
// (curl encodes "user:pass" for you):
//
//	curl -u alice:s3cret http://localhost:3000/private
func ExampleNew() {
	p := passport.New()

	// The verify func receives the decoded username/password and returns the
	// authenticated user. Return basic.ErrInvalidCredentials (or a nil user) to
	// reject the request with a 401 challenge.
	p.Use(basic.New(func(username, password string) (user any, err error) {
		if username == "alice" && password == "s3cret" {
			return username, nil
		}
		return nil, basic.ErrInvalidCredentials
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Basic is stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("basic", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend serves a page that authenticates against a Basic-protected
// endpoint from the browser. Because HTTP Basic credentials live in the
// Authorization header, the page uses fetch() and builds that header with
// btoa("username:password"), which is exactly what the strategy decodes on the
// server. In many cases you do not need this page at all: navigating a browser
// directly to a Basic-protected URL triggers the built-in username/password
// prompt, and this fetch form is for AJAX calls that must supply the header
// themselves. The credentials appear in client script only for the example; a
// real app would collect them from a form. The response text is shown on the page
// so the result is visible.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Basic auth demo</title></head>
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
