package digest_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/digest"
)

// ExampleNew shows the full wiring for simplified HTTP Digest authentication
// (RFC 7616): register the strategy with passport, then guard a route with it.
// Browsers present a native username/password prompt for a Digest challenge, so
// no custom login form is needed.
//
// A client authenticates by echoing the challenge with a computed response;
// curl does the digest handshake for you with --digest:
//
//	curl --digest -u alice:s3cret http://localhost:3000/private
func ExampleNew() {
	p := passport.New()

	// Secret returns the cleartext password (or precomputed HA1) for a user;
	// return "" to reject an unknown user.
	p.Use(digest.New(digest.Options{
		Realm: "Users",
		Secret: func(user string) (ha1OrPassword string) {
			if user == "alice" {
				return "s3cret"
			}
			return ""
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Digest is stateless: skip session creation on success.
	mux.Handle("/private", p.Authenticate("digest", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
