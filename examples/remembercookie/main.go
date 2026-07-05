// Command remembercookie demonstrates persistent "remember me" login using the
// selector/validator cookie scheme. POST /login issues a "remember" cookie
// ("selector:validator") and stores the token server-side; GET / then
// authenticates automatically from that cookie on later visits. POST /logout
// clears it.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/remembercookie"
)

// token is a stored remember-me token keyed by its selector.
type token struct {
	user      string
	validator string
}

var (
	mu     sync.Mutex
	tokens = map[string]token{}
)

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Remember me</title></head>
<body>
  <h1>Persistent login (remember me)</h1>
  <p>Status: <strong>%s</strong></p>
  <form method="POST" action="/login">
    <button type="submit">Log in and remember me</button>
  </form>
  <form method="POST" action="/logout">
    <button type="submit">Forget me</button>
  </form>
  <p>Reload the page after logging in — the "remember" cookie signs you in
     automatically.</p>
</body>
</html>`

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	p := passport.New()

	p.Use(remembercookie.New(remembercookie.Options{
		Lookup: func(selector string) (user any, tokenHash string, err error) {
			mu.Lock()
			defer mu.Unlock()
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

	// GET / authenticates from the remember cookie (Pass when absent).
	mux.Handle("/", p.Authenticate("remember-me")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			status := "not signed in"
			if u := passport.User(r); u != nil {
				status = "signed in as " + u.(string)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, page, status)
		}),
	))

	// POST /login issues a fresh selector/validator and sets the cookie.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		selector := randHex(9)
		validator := randHex(16)
		mu.Lock()
		tokens[selector] = token{user: "alice", validator: validator}
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     remembercookie.CookieName,
			Value:    selector + ":" + validator,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   30 * 24 * 60 * 60,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// POST /logout deletes the stored token and clears the cookie.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(remembercookie.CookieName); err == nil {
			if i := strings.IndexByte(cookie.Value, ':'); i >= 0 {
				mu.Lock()
				delete(tokens, cookie.Value[:i])
				mu.Unlock()
			}
		}
		http.SetCookie(w, &http.Cookie{Name: remembercookie.CookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
