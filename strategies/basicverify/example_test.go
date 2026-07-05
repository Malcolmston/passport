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
