package totp_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/totp"
)

// ExampleNew shows the full wiring for TOTP (RFC 6238) authentication. It
// registers the strategy with a per-user secret lookup and mounts a /verify
// route protected by the code check. The strategy reads the "user" and "code"
// form fields and validates the submitted 6-digit code against the shared secret
// provisioned during enrollment. Verification tolerates a small clock skew, so a
// code from the adjacent 30-second windows is still accepted. On success passport
// establishes the login session before the protected handler runs, and Chain
// installs Initialize and Session so later requests restore the user from the
// session cookie.
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

// Example_frontend renders the browser-facing form used to submit a TOTP code.
// Unlike an OAuth redirect flow, TOTP has no provider to bounce to: the user
// simply reads the current 6-digit code from their authenticator app and posts
// it to the /verify route wired up in ExampleNew. Enrollment happens earlier and
// out of band — the server generates a shared secret and shows it to the user as
// an otpauth:// URI rendered as a QR code, which the authenticator app scans to
// begin generating codes. The form below carries the user identifier in a hidden
// field and the six digits in a numeric input. In a real page the QR code would
// be shown once during enrollment, not on every sign-in.
func Example_frontend() {
	http.HandleFunc("/2fa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Two-factor authentication</title>
<p>Enrollment: scan this QR code with your authenticator app
   (encodes otpauth://totp/Example:alice?secret=BASE32SECRET&issuer=Example).</p>
<form method="post" action="/verify">
  <input type="hidden" name="user" value="alice">
  <label>Authenticator code:
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}"
           maxlength="6" autocomplete="one-time-code" required>
  </label>
  <button type="submit">Verify</button>
</form>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
