package hotp_test

import (
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/hotp"
)

// ExampleNew shows the full wiring for HOTP (RFC 4226) authentication. The
// strategy is registered with passport under its name "hotp", with Secret and
// Counter functions that supply each user's shared secret and current counter
// from application state. The /verify endpoint reads the "user" and "code" form
// fields and checks the submitted code against codes derived from that secret
// and counter, looking ahead a small window to tolerate counter drift. Because
// HOTP codes are single-use, the success handler advances the stored counter
// past the code that was just accepted, preventing replay. The SerializeUser
// and DeserializeUser hooks persist the authenticated user id across the
// session.
func ExampleNew() {
	// Per-user shared secrets and counters (provisioned during enrollment).
	secrets := map[string][]byte{"alice": []byte("12345678901234567890")}
	counters := map[string]uint64{"alice": 0}

	p := passport.New()

	p.Use(hotp.New(hotp.Options{
		Secret:  func(user string) ([]byte, error) { return secrets[user], nil },
		Counter: func(user string) (uint64, error) { return counters[user], nil },
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// POST /verify with form fields "user" and "code".
	mux.Handle("/verify", p.Authenticate("hotp")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := passport.User(r).(string)
			// Advance the stored counter past the code just used.
			counters[user]++
			_, _ = w.Write([]byte("verified " + user))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser side that matches where this strategy
// reads the credential. The hotp strategy reads the user identifier and the
// one-time code from the "user" and "code" form fields, so the page is a plain
// HTML form that POSTs those exact fields to /verify. A standard
// application/x-www-form-urlencoded form submission requires no JavaScript, so
// the code the user copies from their authenticator app or hardware token flows
// straight into the strategy's default fields. The login page is served from a
// local ServeMux only to keep this a runnable, self-contained example; in
// production the same form would be your one-time-password prompt and /verify
// the route protected by the "hotp" strategy.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
  <form method="POST" action="/verify">
    <label>User <input type="text" name="user"></label>
    <label>Code <input type="text" name="code" inputmode="numeric"></label>
    <button type="submit">Verify</button>
  </form>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
