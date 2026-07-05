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

// ExampleNew shows the full wiring for the refresh-token JWT strategy. It
// registers the strategy with passport and mounts a refresh endpoint protected
// by the "refresh-jwt" strategy. That endpoint runs only when a valid, unexpired
// refresh_token cookie is present, and on success the token's claims become the
// authenticated user so the handler can mint a fresh access token. The example
// also uses Issue to mint a refresh token with a 30-day TTL, which a real app
// would set as an HttpOnly cookie right after a primary login. Because the cookie
// is sent automatically by the browser, no request body or header is needed on
// the refresh call.
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

// Example_frontend shows the browser side of the refresh-JWT flow. The refresh
// token lives in an HttpOnly cookie, so JavaScript cannot read it; the browser
// simply attaches it automatically when the page calls the refresh endpoint. The
// snippet below fetches /auth/refresh with credentials included so the
// refresh_token cookie is sent, then uses the returned access token for
// subsequent API calls. A real app calls this transparently when an access token
// nears expiry. Because the credential is a cookie, there is no header or form
// field to populate on the client.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <script>
      // The HttpOnly refresh_token cookie rides along automatically because of
      // credentials:"include"; the server mints a new access token in response.
      async function refresh() {
        const res = await fetch("/auth/refresh", { credentials: "include" });
        return res.ok ? res.text() : Promise.reject(new Error("re-login required"));
      }
      refresh().catch(() => { window.location = "/login"; });
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
