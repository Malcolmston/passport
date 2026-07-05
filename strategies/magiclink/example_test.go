package magiclink_test

import (
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/magiclink"
)

// ExampleNew shows the full server-side wiring for passwordless "magic link"
// login. It registers the strategy with a signing secret and teaches passport to
// serialize the authenticated email into the session. The /send endpoint mints a
// signed, time-limited token with magiclink.Sign, embeds it in a link, and (in
// real code) emails that link to the user. The /verify endpoint is guarded by the
// strategy, which validates the token from the "?token=" query parameter and, on
// success, establishes the session for the embedded email. Because the token is
// stateless, its 15-minute expiry is what bounds how long a leaked link stays
// usable.
func ExampleNew() {
	secret := []byte("replace-with-a-32-byte-random-secret")

	p := passport.New()

	// The authenticated user is the email embedded in the token.
	p.Use(magiclink.New(magiclink.Options{Secret: secret}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// POST /send?email=... mints a link and (in real code) emails it.
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		token := magiclink.Sign(secret, email, time.Now().Add(15*time.Minute))
		link := "https://app.example.com/verify?token=" + token
		// Deliver `link` to `email` here. For the demo we just echo it.
		_, _ = w.Write([]byte("magic link: " + link))
	})

	// GET /verify?token=... authenticates and establishes the session.
	mux.Handle("/verify", p.Authenticate("magic-link", passport.Options{SuccessRedirect: "/"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("logged in as " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser side of magic-link login: an HTML form that
// POSTs an email address to the /send route from ExampleNew. There is no password
// field, because the user proves control of the address by clicking the link that
// arrives in their inbox. The server mints a signed token, emails a link such as
// https://app.example.com/verify?token=..., and the user's click lands on the
// /verify route where the strategy authenticates the token. That verify step, not
// this form, is where the session is established. This handler only renders the
// request form.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<form method="post" action="/send">
  <input name="email" type="email" placeholder="you@example.com">
  <button type="submit">Email me a magic link</button>
</form>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
