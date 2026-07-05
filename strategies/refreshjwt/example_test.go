package refreshjwt_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/refreshjwt"
)

// ExampleNew shows the full wiring for the refresh-token JWT strategy: register
// it with passport, mount a protected refresh endpoint, and mint a refresh
// token to hand back to the client in a cookie.
func ExampleNew() {
	secret := []byte("refresh-signing-secret")

	strategy := refreshjwt.New(refreshjwt.Options{Secret: secret})

	p := passport.New()
	p.Use(strategy)

	// A route protected by the "refresh-jwt" strategy. It runs only when a
	// valid, unexpired refresh_token cookie is present; on success the token's
	// claims become the authenticated user, and you can mint a fresh access
	// token here.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "refreshed for %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The client sends the cookie automatically:
	//   curl --cookie "refresh_token=<jwt>" https://app.example.com/auth/refresh
	mux.Handle("/auth/refresh", p.Authenticate("refresh-jwt")(protected))

	// After a primary login, issue a refresh token and set it as a cookie.
	token, err := strategy.Issue("user-123", 30*24*time.Hour, jwt.Claims{"scope": "api"})
	if err != nil {
		log.Fatal(err)
	}
	_ = token

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
