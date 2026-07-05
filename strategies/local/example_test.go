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

// ExampleNew shows the full wiring for the local (username/password) strategy:
// register it with a verify function, teach passport how to serialize the user
// into the session, then mount a login endpoint and a protected route.
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
