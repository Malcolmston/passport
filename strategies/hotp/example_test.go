package hotp_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/hotp"
)

// ExampleNew shows the full wiring for HOTP (RFC 4226) authentication. The
// verify endpoint reads the "user" and "code" form fields and checks the
// submitted code against the user's shared secret and current counter, looking
// ahead a small window to tolerate counter drift.
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
