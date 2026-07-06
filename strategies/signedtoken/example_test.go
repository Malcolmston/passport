package signedtoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/signedtoken"
)

// ExampleNew shows the full wiring for the signedtoken strategy. It mints a
// token with Sign, registers the strategy under its name "signed-token", and
// mounts an /api/me route guarded by the token check. The token is
// self-contained — HMAC-SHA256-signed JSON claims — so verification needs no
// server-side session or database. On a valid token the decoded claims map
// becomes the authenticated user, which the protected handler reads with
// passport.User. Chain installs passport for every request; for a purely
// stateless API you could additionally pass passport.Options{Session: false} to
// Authenticate so no cookie is set.
//
// A client supplies the token in the Authorization header as a bearer token:
//
//	curl -H "Authorization: Bearer <base64url(claims)>.<hex(hmac)>" \
//	    https://app.example.com/api/me
func ExampleNew() {
	secret := []byte("super-secret-hmac-key")

	// Mint a signed token carrying the caller's claims (e.g. at login).
	token, err := signedtoken.Sign(secret, map[string]any{
		"sub":  "user-42",
		"role": "admin",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = token // hand this to the client; it presents it as a bearer token.

	p := passport.New()

	// Register the strategy. It verifies the signature (and any "exp" claim)
	// with the shared secret; the decoded claims become the authenticated user.
	p.Use(signedtoken.New(signedtoken.Options{
		Secret: secret,
	}))

	// A protected handler that reads the authenticated user (the claims map).
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := passport.User(r).(map[string]any)
		fmt.Fprintf(w, "hello %v", claims["sub"])
	})

	mux := http.NewServeMux()
	// The strategy name is "signed-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("signed-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of stateless token authentication.
// There is no redirect and no login form to post here: the token is obtained
// once (for example returned by a login endpoint) and then attached to every API
// call. The page below stashes the token in memory and uses fetch() to call the
// protected /api/me route, setting the "Authorization: Bearer <token>" header
// that the strategy reads on the server. Because the token is a bearer
// credential, keep it out of localStorage where practical and never log it. The
// same header works from any HTTP client, which is why this strategy suits
// single-page apps, mobile clients, and service-to-service calls.
func Example_frontend() {
	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>API client</title>
<button id="load">Load my profile</button>
<pre id="out"></pre>
<script>
  // token would normally come from your login response.
  const token = "PASTE_SIGNED_TOKEN_HERE";
  document.getElementById("load").addEventListener("click", async () => {
    const res = await fetch("/api/me", {
      headers: { "Authorization": "Bearer " + token },
    });
    document.getElementById("out").textContent =
      res.ok ? await res.text() : "unauthorized (" + res.status + ")";
  });
</script>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
