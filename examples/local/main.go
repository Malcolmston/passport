// Command local demonstrates username/password authentication with
// passport-go using the local strategy and a session-backed login. It serves
// an HTML login form on GET / and authenticates the POST /login submission.
package main

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/local"
)

// User is a trivial application user type.
type User struct {
	ID   string
	Name string
}

// accounts is a trivial in-memory user table. Real code would hash passwords.
var accounts = map[string]struct {
	User
	Password string
}{
	"alice": {User{ID: "1", Name: "Alice"}, "password123"},
}

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Local login</title></head>
<body>
  <h1>Sign in</h1>
  <form method="POST" action="/login">
    <label>Username <input name="username" value="alice"></label><br>
    <label>Password <input name="password" type="password" value="password123"></label><br>
    <button type="submit">Log in</button>
  </form>
  <p><a href="/profile">View profile</a> &middot; <a href="/logout">Log out</a></p>
</body>
</html>`

func main() {
	p := passport.New()

	// Register the local (username/password) strategy.
	p.Use(local.New(func(username, password string) (any, error) {
		if rec, ok := accounts[username]; ok && rec.Password == password {
			return rec.User, nil
		}
		return nil, local.ErrInvalidCredentials
	}))

	// Teach passport how to store and restore the user in the session.
	p.SerializeUser(func(u any) (string, error) { return u.(User).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		for _, rec := range accounts {
			if rec.User.ID == id {
				return rec.User, nil
			}
		}
		return nil, nil
	})

	mux := http.NewServeMux()

	// GET / serves the login form.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	// POST /login authenticates the form submission.
	mux.Handle("/login", p.Authenticate("local", passport.Options{SuccessRedirect: "/profile"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/profile", http.StatusFound)
		}),
	))

	// GET /profile requires an authenticated session.
	mux.Handle("/profile", p.RequireLogin("/")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(User)
			_, _ = w.Write([]byte("Profile of " + u.Name))
		}),
	))

	// GET /logout clears the session.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = p.LogOut(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
