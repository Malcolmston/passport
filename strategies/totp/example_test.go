package totp_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/totp"
)

// ExampleNew shows the full wiring for TOTP (RFC 6238) authentication. The
// verify endpoint reads the "user" and "code" form fields and checks the
// submitted 6-digit code against the user's shared secret.
func ExampleNew() {
	// Per-user shared secrets (provisioned during enrollment).
	secrets := map[string][]byte{
		"alice": []byte("12345678901234567890"),
	}

	p := passport.New()

	p.Use(totp.New(totp.Options{
		Secret: func(user string) ([]byte, error) {
			return secrets[user], nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// POST /verify with form fields "user" and "code".
	mux.Handle("/verify", p.Authenticate("totp")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("verified " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}
