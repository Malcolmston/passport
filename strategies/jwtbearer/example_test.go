package jwtbearer_test

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwtbearer"
)

// ExampleNew shows the full wiring for the RFC 7523 JWT bearer grant. It
// registers the strategy with passport, here using an HS256 shared secret,
// though setting JWKSURL instead would verify RS256/ES256 assertions against
// the issuer's published keys. It then mounts a token endpoint under the
// "jwt-bearer" strategy name, so the handler runs only after a valid assertion
// is verified. On success the verified assertion claims become the
// authenticated user, retrieved with passport.User(r). A client authenticates
// by POSTing an "assertion" form field (spec clients also send
// grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer), for example: curl -d
// "assertion=<jwt>" https://app.example.com/oauth/token. Finally it installs
// passport for every request with passport.Chain and serves.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. Use Secret for HS256 assertions, or set JWKSURL to
	// verify RS256/ES256 assertions against the issuer's published keys.
	p.Use(jwtbearer.New(jwtbearer.Options{
		Secret: []byte("shared-assertion-secret"),
	}))

	// A route protected by the "jwt-bearer" strategy. On success the assertion
	// claims become the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "granted: %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Client POSTs grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer and
	// assertion=<jwt> as form fields:
	//   curl -d "assertion=<jwt>" https://app.example.com/oauth/token
	mux.Handle("/oauth/token", p.Authenticate("jwt-bearer")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side that matches the JWT bearer strategy.
// The strategy reads the assertion from the "assertion" POST form field, so the
// page's script must submit an x-www-form-urlencoded body carrying that field.
// Here the client holds a signed JWT assertion and POSTs it to the token
// endpoint together with the RFC 7523 grant_type value
// urn:ietf:params:oauth:grant-type:jwt-bearer. The Content-Type is set to
// application/x-www-form-urlencoded so the server parses the form and finds the
// assertion. The login route below serves the HTML page; a real client would
// obtain the assertion by signing claims with its issuer key. This mirrors the
// server wiring in ExampleNew, which reads the "assertion" form field.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
<script>
const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
const body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + encodeURIComponent(jwt);
fetch("/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: body
})
  .then(r => r.text())
  .then(t => console.log(t));
</script>
</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
