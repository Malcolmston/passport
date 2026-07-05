package magiclink_test

import (
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/magiclink"
)

// ExampleNew shows the full wiring for passwordless "magic link" login: an
// endpoint mints a signed, time-limited token (delivered by email), and the
// verify endpoint authenticates the token presented in the "?token=" query
// parameter.
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
