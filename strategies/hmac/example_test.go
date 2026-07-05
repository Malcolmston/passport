package hmac_test

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/hmac"
)

// ExampleNew shows the full wiring for the hmac strategy. It registers the
// strategy with passport, configuring the signature header, the key-id header,
// and a per-key Secret lookup that returns nil for unknown keys. It then mounts
// a route under the "hmac" strategy name, so the handler runs only after the
// recomputed HMAC-SHA256 of the raw body matches the presented signature in
// constant time. On success the key id becomes the authenticated user,
// retrieved with passport.User(r). A client signs the raw request body with the
// shared secret, hex-encodes the digest, and sends it in the signature header
// along with the key id, for example:
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

// Example_frontend shows the browser side that matches the hmac strategy. The
// strategy verifies an HMAC-SHA256 signature of the raw request body, read as
// lowercase hex from "X-Signature", with the key id in "X-Key-Id". The page's
// script imports the shared secret into the Web Crypto API, signs the exact
// bytes it is about to POST, and hex-encodes the resulting digest so it matches
// what the server recomputes. It then fetches POST /webhook with the same body,
// sending the key id in "X-Key-Id" and the lowercase-hex signature in
// "X-Signature", exactly the headers the server reads. Because the signature
// covers the raw body, the script must sign and send the identical bytes. This
// mirrors the server wiring in ExampleNew.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
<script>
async function send() {
  const secret = "shared-secret";
  const body = JSON.stringify({ event: "ping" });
  const key = await window.crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await window.crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(body));
  const sig = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  await fetch("/webhook", {
    method: "POST",
    headers: { "X-Key-Id": "client-1", "X-Signature": sig },
    body: body
  });
}
send();
</script>
</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
