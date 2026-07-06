package sessiontoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/sessiontoken"
)

// ExampleNew shows the full wiring for the sessiontoken strategy: register it
// with passport, then mount a route protected by the session-token check.
// The Verify func is typically a session-store lookup.
//
// A client supplies the opaque session token in the configured cookie (here
// "session"):
//
//	curl --cookie "session=opaque-session-id" https://app.example.com/api/me
func ExampleNew() {
	p := passport.New()

	// A trivial in-memory session store standing in for the real thing.
	sessions := map[string]string{"opaque-session-id": "user-42"}

	// Register the strategy. The Verify func maps a session token to your
	// application user; return a nil user (or sessiontoken.ErrInvalidToken) for
	// an unknown or expired session.
	p.Use(sessiontoken.New(sessiontoken.Options{
		Cookie: "session",
		Verify: func(token string) (user any, err error) {
			uid, ok := sessions[token]
			if !ok {
				return nil, sessiontoken.ErrInvalidToken
			}
			return uid, nil
		},
	}))

	// A protected handler that reads the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "session-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("session-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
