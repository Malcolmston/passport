package headertoken_test

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/headertoken"
)

// ExampleNew shows the full wiring for the headertoken strategy. It registers
// the strategy with passport, configuring the header the token is read from and
// a Verify func that maps a raw token to an application user. It then mounts a
// protected route under the strategy's registered name, "header-token", so the
// handler runs only after the token is verified. Inside the handler the
// authenticated user is retrieved with passport.User(r). Finally it installs
// passport for every request with passport.Chain and starts the server; a
// client authenticates by sending the token in the configured request header,
// for example: curl -H "X-Auth-Token: s3cr3t-token" https://app.example.com/api/me.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The Verify func maps a raw token to your
	// application user; return a nil user (or headertoken.ErrInvalidToken) to
	// reject the request.
	p.Use(headertoken.New(headertoken.Options{
		Header: "X-Auth-Token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, headertoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	// A protected handler that reads the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "header-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("header-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side that matches the headertoken
// strategy. The strategy reads the credential from a custom request header, so
// the page's script must place the token in that same header when calling the
// API. Here the client keeps a token in a variable and sends it in the
// "X-Auth-Token" header via fetch, exactly the header the server reads by
// default. The login route below simply serves the HTML page; a real
// deployment would obtain the token from a prior sign-in step. This mirrors the
// server wiring in ExampleNew, where the strategy is configured to read
// "X-Auth-Token".
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
<script>
const token = "s3cr3t-token";
fetch("/api/me", { headers: { "X-Auth-Token": token } })
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
