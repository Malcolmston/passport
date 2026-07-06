package ldap_test

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/ldap"
)

// ExampleNew shows the full server-side wiring for the LDAP strategy: register it
// with passport, then guard a login route with it. The strategy reads the
// username and password from the submitted form and expands the username into a
// distinguished name using DNTemplate. It then calls the configured Bind function
// with that DN and the presented password to authenticate against the directory.
// The Bind function is the single integration point where a real LDAP dial, TLS
// negotiation, and bind belong; this example stubs it with one well-known
// credential. The protected handler runs only after a successful bind, once
// passport has established the session.
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

// Example_frontend shows the browser side of LDAP login: an HTML form that POSTs
// the username and password to the /login route guarded by the strategy in
// ExampleNew. It looks exactly like an ordinary username/password form, and the
// field names match the strategy's UserField and PassField. The difference is
// entirely server-side: instead of comparing a stored password, the strategy
// binds to the directory server as the user to verify the credentials. On a
// successful bind passport establishes the session and the protected handler
// runs; a failed bind yields an HTTP 401. This handler only renders the form.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Log in</title>
<form method="post" action="/login">
  <input name="username" placeholder="Directory username">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
