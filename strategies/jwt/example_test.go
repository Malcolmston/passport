package jwt_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// ExampleNew shows the full wiring for the JWT strategy: register it with
// passport, mount a protected route, and issue an HS256 token clients present.
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
