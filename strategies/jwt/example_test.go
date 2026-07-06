package jwt_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// ExampleNew shows the full wiring for the JWT strategy. It registers the
// strategy with passport using the HMAC secret and a verify func that maps the
// token's claims to an application user. It then mounts a route under the "jwt"
// strategy name, so the protected handler runs only after a valid HS256 bearer
// token is verified and its exp/nbf claims are checked. It issues a token with
// the Sign helper to illustrate the claims a client would carry. A client
// authenticates by sending that token in the Authorization header, for example:
// curl -H "Authorization: Bearer <jwt>" https://app.example.com/api/me. Finally
// it installs passport for every request with passport.Chain and serves.
func ExampleNew() {
	secret := []byte("my-256-bit-secret")

	p := passport.New()

	// Register the strategy. The verify func maps the token's claims to your
	// application user (return a nil user to reject the token).
	p.Use(jwt.New(secret, func(claims jwt.Claims) (user any, err error) {
		return claims.Subject(), nil
	}))

	// A route protected by the "jwt" strategy. It only runs after a valid
	// bearer token is verified.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	mux.Handle("/api/me", p.Authenticate("jwt")(protected))

	// Issue a token for a subject; a client sends it back on each request:
	//   curl -H "Authorization: Bearer <jwt>" https://app.example.com/api/me
	token, err := jwt.Sign(secret, jwt.Claims{
		"sub": "user-123",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = token

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side that matches the JWT strategy. The
// strategy extracts the token from the "Authorization: Bearer <jwt>" header, so
// the page's script must send the JWT there. Here the client holds a
// previously issued token and calls the API with fetch, setting the
// Authorization header to "Bearer " followed by the token. The login route
// below serves the HTML page; in practice the JWT would come from a sign-in
// endpoint that signs it with the same secret the server verifies against. This
// matches the server wiring in ExampleNew, which reads bearer tokens from the
// Authorization header.
func Example_frontend() {
	const page = `<!doctype html>
<html><body>
<script>
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
fetch("/api/me", { headers: { "Authorization": "Bearer " + token } })
  .then(r => r.text())
  .then(t => console.log(t));
</script>
</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
}
