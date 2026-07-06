package hmac_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/hmac"
)

// ExampleNew shows the full wiring for the hmac strategy: register it with
// passport, then mount a route protected by an HMAC-SHA256 body-signature
// check. On success the key id becomes the authenticated user.
//
// A client signs the raw request body with the shared secret and supplies the
// lowercase-hex signature in the signature header (here "X-Signature"), plus
// the key id in the key-id header (here "X-Key-Id"):
//
//	sig=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
//	curl -X POST --data "$BODY" \
//	    -H "X-Key-Id: client-1" -H "X-Signature: $sig" \
//	    https://app.example.com/webhook
func ExampleNew() {
	p := passport.New()

	// Per-key secrets. Secret returns nil for an unknown key id, which the
	// strategy rejects.
	secrets := map[string][]byte{"client-1": []byte("shared-secret")}

	// Register the strategy. It reads the signature from "X-Signature" and the
	// key id from "X-Key-Id", recomputes the HMAC over the raw body, and
	// compares in constant time.
	p.Use(hmac.New(hmac.Options{
		Header:      "X-Signature",
		KeyIDHeader: "X-Key-Id",
		Secret: func(keyID string) []byte {
			return secrets[keyID]
		},
	}))

	// A protected handler that reads the authenticated user (the key id).
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "verified webhook from %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "hmac" (from Strategy.Name()).
	mux.Handle("/webhook", p.Authenticate("hmac")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
