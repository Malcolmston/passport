package digest_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/digest"
)

// ExampleNew shows the full wiring for simplified HTTP Digest authentication (RFC
// 7616): register the strategy with passport, then guard a route with it. The
// Options.Secret callback returns the cleartext password (or precomputed HA1) for
// a username, and returning an empty string rejects an unknown user. When a
// request arrives without a valid Digest header the strategy issues a
// WWW-Authenticate challenge, and the browser responds by showing its native
// username/password prompt, so no custom login form is needed. On a matching
// response the username becomes the authenticated user. The protected route is
// mounted with passport.Options{Session: false} because Digest is stateless.
//
// A client authenticates by echoing the challenge with a computed response; curl
// does the digest handshake for you with --digest:
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

// Example_frontend shows the browser side of HTTP Digest, which is unusual in that
// there is no login form to build. The browser itself renders a native
// username/password dialog whenever it receives the WWW-Authenticate challenge
// that the strategy sends for the protected resource. So the only "frontend" you
// need is a way to reach that resource: this page serves a plain link to the
// Digest-protected route, and following it triggers the browser prompt. Once the
// user enters valid credentials the browser computes the digest response and
// retries automatically, and it remembers the credentials for the realm for the
// rest of the session.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Members area</title>
<!-- Following this link to a Digest-protected resource makes the browser show
     its native username/password dialog; no custom form is needed. -->
<a href="/private">Enter the members area</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
