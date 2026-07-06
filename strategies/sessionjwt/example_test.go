package sessionjwt_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/sessionjwt"
)

// ExampleNew shows the full wiring for the stateless session JWT strategy:
// register it with passport, mount a protected route, and establish a session
// by minting a signed cookie after a primary login.
func ExampleNew() {
	strategy := sessionjwt.New(sessionjwt.Options{
		Secret: []byte("session-signing-secret"),
	})

	p := passport.New()
	p.Use(strategy)

	// After a primary login, mint a session JWT and write it as a cookie.
	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := strategy.Issue(jwt.Claims{"sub": "user-123"}, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		strategy.SetCookie(w, token)
	})

	// A route protected by the "session-jwt" strategy. It runs only when a
	// valid session cookie is present; the cookie's claims become the user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	// The browser sends the session cookie automatically:
	//   curl --cookie "session=<jwt>" https://app.example.com/dashboard
	mux.Handle("/dashboard", p.Authenticate("session-jwt")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
