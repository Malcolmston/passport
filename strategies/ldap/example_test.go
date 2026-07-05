package ldap_test

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/ldap"
)

// ExampleNew shows the full wiring for the LDAP strategy: register it with
// passport, then guard a route with it. The strategy reads the username and
// password from the request form, expands the username into a distinguished
// name using DNTemplate, and authenticates by performing an LDAP bind.
func ExampleNew() {
	p := passport.New()

	// The Bind func performs the actual LDAP bind against your directory server
	// (host, TLS, and connection handling live here). Return a non-nil user on
	// a successful bind, or a nil user / error to reject.
	p.Use(ldap.New(ldap.Options{
		// "uid=alice,ou=people,dc=example,dc=com" for username "alice".
		DNTemplate: "uid=%s,ou=people,dc=example,dc=com",
		UserField:  "username",
		PassField:  "password",
		Bind: func(dn, password string) (user any, err error) {
			// Dial "ldap.example.com:389" and bind as dn/password here. This
			// stub accepts a single well-known credential for illustration.
			if dn == "uid=alice,ou=people,dc=example,dc=com" && password == "s3cret" {
				return dn, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}))

	// The protected handler only runs after a successful bind.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// POST /login with form fields "username" and "password".
	mux.Handle("/login", p.Authenticate("ldap")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
