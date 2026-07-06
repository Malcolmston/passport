package local_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

// user is a trivial application user type.
type user struct {
	ID   string
	Name string
}

// ExampleNew shows the full server-side wiring for the local (username/password)
// strategy. It registers the strategy with a verify function that looks the
// submitted credentials up in an in-memory account table, returning the user on a
// match and local.ErrInvalidCredentials otherwise. It then teaches passport how
// to serialize the user into the session and restore it on later requests. The
// /login route is guarded by the strategy, so its handler runs only after a
// successful password check, while /profile is guarded by RequireLogin and needs
// an established session. Real code would hash and compare passwords rather than
// compare them in plaintext.
func ExampleNew() {
	// A trivial in-memory user table. Real code would hash passwords.
	accounts := map[string]struct {
		user
		password string
	}{
		"alice": {user{ID: "1", Name: "Alice"}, "password123"},
	}

	p := passport.New()

	// Register the local strategy. The verify func returns the authenticated
	// user, or local.ErrInvalidCredentials on a bad username/password.
	p.Use(local.New(func(username, password string) (any, error) {
		if rec, ok := accounts[username]; ok && rec.password == password {
			return rec.user, nil
		}
		return nil, local.ErrInvalidCredentials
	}))

	// Teach passport how to store and restore the user in the session.
	p.SerializeUser(func(u any) (string, error) { return u.(user).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		for _, rec := range accounts {
			if rec.user.ID == id {
				return rec.user, nil
			}
		}
		return nil, nil
	})

	mux := http.NewServeMux()

	// POST /login with form fields "username" and "password".
	mux.Handle("/login", p.Authenticate("local")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(user)
			_, _ = w.Write([]byte("Logged in as " + u.Name))
		}),
	))

	// GET /profile requires an authenticated session.
	mux.Handle("/profile", p.RequireLogin("/")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(user)
			_, _ = w.Write([]byte("Profile of " + u.Name))
		}),
	))

	// Install passport for every request, then serve.
	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser side of the local (username/password)
// login: an HTML form that POSTs the two credential fields to the /login route
// guarded by the strategy in ExampleNew. The form's method is POST and its action
// is the login route, so the browser sends the username and password in the
// request body. The field names "username" and "password" match the strategy's
// defaults, so no extra configuration is needed. On a correct password passport
// establishes the session and the login handler runs; on a bad password the
// strategy responds with an HTTP 401. This handler only renders the form; the
// credential check happens server-side.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Log in</title>
<form method="post" action="/login">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
