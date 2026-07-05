package remembercookie_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/remembercookie"
)

// ExampleNew shows the full wiring for persistent "remember me" login using the
// selector/validator cookie scheme. On each request the strategy reads the
// "remember" cookie ("selector:validator"), resolves the selector to a stored
// token hash, and compares the validator against it in constant time. The Lookup
// func stands in for your token store, returning the user and stored validator
// hash for a selector or a nil user when the selector is unknown. SerializeUser
// and DeserializeUser persist the recognized user across requests through the
// passport session. Note that the strategy Pass()es when no remember cookie is
// present, so the handler still runs for anonymous visitors and passport.User is
// simply nil.
func ExampleNew() {
	// A stored remember-me token: selector -> (user, validator hash).
	type token struct {
		user      string
		validator string
	}
	tokens := map[string]token{
		"sel123": {user: "alice", validator: "secret-validator"},
	}

	p := passport.New()

	p.Use(remembercookie.New(remembercookie.Options{
		Lookup: func(selector string) (user any, tokenHash string, err error) {
			t, ok := tokens[selector]
			if !ok {
				return nil, "", nil
			}
			return t.user, t.validator, nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// The strategy Pass()es when there is no remember cookie, so the handler
	// still runs — passport.User(r) is nil for anonymous requests.
	mux.Handle("/", p.Authenticate("remember-me")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u := passport.User(r); u != nil {
				_, _ = w.Write([]byte("welcome back, " + u.(string)))
				return
			}
			_, _ = w.Write([]byte("hello, stranger"))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser side of "remember me" login. The remember
// cookie is not set by JavaScript; instead the login form carries a "remember me"
// checkbox, and the server issues the persistent selector:validator cookie only
// when that box is checked. The form below posts the username, password and the
// remember flag to the primary login endpoint. On a later visit the browser
// sends the remember cookie automatically, and the strategy logs the user back in
// without a password. Because the cookie should be HttpOnly, there is nothing for
// client-side script to read or manage.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <label>
        <!-- When checked, the server sets the persistent "remember" cookie. -->
        <input type="checkbox" name="remember" value="1"> Remember me
      </label>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
