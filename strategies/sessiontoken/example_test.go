package sessiontoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/sessiontoken"
)

// ExampleNew shows the full wiring for the sessiontoken strategy. It registers
// the strategy with passport and mounts a route protected by the "session-token"
// check. The Verify func is typically a session-store lookup; here a trivial
// in-memory map stands in for a real store, returning the user for a known token
// and ErrInvalidToken otherwise. On success the protected handler runs with the
// resolved user available via passport.User. The client supplies the opaque
// session token in the configured cookie, which the browser sends automatically:
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

// Example_frontend shows the browser side of an opaque session-cookie login. The
// session token is stored in an HttpOnly cookie the server sets at login, so
// client-side script cannot read it and the browser attaches it automatically.
// The snippet fetches a protected API route with credentials included so the
// session cookie is sent, and redirects to the login page if the session is no
// longer valid. A real app never handles the token value directly on the client.
// Because the credential is a cookie, no Authorization header is required.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <script>
      // The HttpOnly session cookie rides along because of credentials:"include".
      async function loadProfile() {
        const res = await fetch("/api/me", { credentials: "include" });
        if (!res.ok) { window.location = "/login"; return; }
        document.body.append(await res.text());
      }
      loadProfile();
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
