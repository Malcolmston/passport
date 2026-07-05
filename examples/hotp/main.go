// Command hotp demonstrates HMAC-based One-Time Password (RFC 4226)
// authentication. GET / serves a form and, for convenience, displays the code
// valid for the demo user's current counter so you can try it without a
// hardware token. POST /verify checks the code and advances the counter.
package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/hotp"
)

var (
	mu       sync.Mutex
	secrets  = map[string][]byte{"alice": []byte("12345678901234567890")}
	counters = map[string]uint64{"alice": 0}
)

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>HOTP login</title></head>
<body>
  <h1>One-time password sign in (HOTP)</h1>
  <p>Demo: the code valid for <code>alice</code> at counter {{.Counter}} is
     <strong>{{.Code}}</strong> (normally from your hardware token).</p>
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

	p.Use(hotp.New(hotp.Options{
		Secret: func(user string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			return secrets[user], nil
		},
		Counter: func(user string) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			return counters[user], nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// GET / serves the form, pre-filled with the current valid demo code.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counter := counters["alice"]
		code := hotp.Generate(secrets["alice"], counter)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{"Code": code, "Counter": counter})
	})

	// POST /verify checks the code, then advances the stored counter.
	mux.Handle("/verify", p.Authenticate("hotp")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := passport.User(r).(string)
			mu.Lock()
			counters[user]++
			mu.Unlock()
			_, _ = w.Write([]byte("verified " + user + " — counter advanced"))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
