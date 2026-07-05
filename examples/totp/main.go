// Command totp demonstrates Time-based One-Time Password (RFC 6238)
// authentication. GET / serves a form to submit a user and 6-digit code, and
// for convenience displays the code currently valid for the demo user so you
// can try it without an authenticator app. POST /verify checks the code.
package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/totp"
)

// secrets holds per-user shared secrets provisioned during enrollment.
var secrets = map[string][]byte{
	"alice": []byte("12345678901234567890"),
}

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>TOTP login</title></head>
<body>
  <h1>Two-factor sign in (TOTP)</h1>
  <p>Demo: the code currently valid for <code>alice</code> is
     <strong>{{.Code}}</strong> (normally from your authenticator app).</p>
  <form method="POST" action="/verify">
    <label>User <input name="user" value="alice"></label><br>
    <label>Code <input name="code" value="{{.Code}}"></label><br>
    <button type="submit">Verify</button>
  </form>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(page))

func main() {
	p := passport.New()

	p.Use(totp.New(totp.Options{
		Secret: func(user string) ([]byte, error) { return secrets[user], nil },
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// GET / serves the form, pre-filled with the currently valid demo code.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := totp.Generate(secrets["alice"], time.Now())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{"Code": code})
	})

	// POST /verify checks the submitted code.
	mux.Handle("/verify", p.Authenticate("totp", passport.Options{SuccessRedirect: "/profile"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/profile", http.StatusFound)
		}),
	))

	// GET /profile requires an authenticated session.
	mux.Handle("/profile", p.RequireLogin("/")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("verified " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
