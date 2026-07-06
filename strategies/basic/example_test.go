package basic_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/basic"
)

// ExampleNew shows the full wiring for HTTP Basic authentication (RFC 7617):
// register the strategy with passport, then guard a route with it. Browsers
// present a native username/password prompt for a Basic challenge, so no custom
// login form is needed.
//
// A client authenticates by sending the credentials in the Authorization
// header (curl encodes "user:pass" for you):
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
