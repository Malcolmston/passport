// Command magiclink demonstrates passwordless "magic link" authentication. The
// user submits an email on GET /, the server mints a signed, time-limited token
// and (in real code) emails a link to /verify?token=..., which authenticates
// the user. For the demo the link is shown on screen instead of emailed.
package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/magiclink"
)

var secret = []byte("replace-with-a-32-byte-random-secret")

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Magic link login</title></head>
<body>
  <h1>Passwordless sign in</h1>
  <form method="POST" action="/send">
    <label>Email <input name="email" type="email" value="alice@example.com"></label>
    <button type="submit">Email me a link</button>
  </form>
  {{if .Link}}
  <p>For the demo, click your magic link:</p>
  <p><a href="{{.Link}}">{{.Link}}</a></p>
  {{end}}
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(page))

func main() {
	p := passport.New()

	// The authenticated user is the email embedded in the token.
	p.Use(magiclink.New(magiclink.Options{Secret: secret}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// GET / serves the email form.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{"Link": ""})
	})

	// POST /send mints a link. Real code would email it; here we render it.
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		token := magiclink.Sign(secret, email, time.Now().Add(15*time.Minute))
		link := "/verify?token=" + token
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{"Link": link})
	})

	// GET /verify?token=... authenticates and establishes the session.
	mux.Handle("/verify", p.Authenticate("magic-link", passport.Options{SuccessRedirect: "/profile"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/profile", http.StatusFound)
		}),
	))

	// GET /profile requires an authenticated session.
	mux.Handle("/profile", p.RequireLogin("/")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("logged in as " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
