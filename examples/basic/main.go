// Command basic demonstrates username/password authentication with passport-go
// using the local strategy and session-backed login.
package main

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

type User struct {
	ID   string
	Name string
}

// A trivial in-memory user table. Passwords would be hashed in real code.
var users = map[string]struct {
	User
	Password string
}{
	"alice": {User{ID: "1", Name: "Alice"}, "password123"},
}

func main() {
	p := passport.New()

	// Register the local (username/password) strategy.
	p.Use(local.New(func(username, password string) (any, error) {
		if rec, ok := users[username]; ok && rec.Password == password {
			return rec.User, nil
		}
		return nil, local.ErrInvalidCredentials
	}))

	// Teach passport how to store and restore a user in the session.
	p.SerializeUser(func(u any) (string, error) { return u.(User).ID, nil })
	p.DeserializeUser(func(id string, r *http.Request) (any, error) {
		for _, rec := range users {
			if rec.User.ID == id {
				return rec.User, nil
			}
		}
		return nil, nil
	})

	mux := http.NewServeMux()

	// POST /login  (form or JSON: username, password)
	mux.Handle("/login", p.Authenticate("local")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(User)
			w.Write([]byte("Logged in as " + u.Name))
		}),
	))

	// GET /profile  (requires an authenticated session)
	mux.Handle("/profile", p.RequireLogin("")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(User)
			w.Write([]byte("Profile of " + u.Name))
		}),
	))

	// POST /logout
	mux.Handle("/logout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = p.LogOut(w, r)
		w.Write([]byte("Logged out"))
	}))

	// Install passport for every request.
	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
