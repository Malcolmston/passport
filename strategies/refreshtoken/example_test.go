package refreshtoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/refreshtoken"
)

// ExampleNew shows the full wiring for the OAuth2 refresh-token strategy. It
// registers the strategy with passport and mounts a token endpoint protected by
// the "refresh-token" strategy. The verify func looks the presented token up in
// your store and returns the associated user, returning ErrInvalidToken to
// reject an unknown or revoked token. On success the protected handler runs with
// the resolved user available via passport.User, where a real app would mint and
// return a fresh access token. The client presents the token in the request
// body, either as a form field or as JSON.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func looks the token up in your store
	// and returns the associated user (return ErrInvalidToken to reject it).
	p.Use(refreshtoken.New(func(token string) (user any, err error) {
		if token != "stored-refresh-token" {
			return nil, refreshtoken.ErrInvalidToken
		}
		return "user-123", nil
	}))

	// A route protected by the "refresh-token" strategy. On success mint and
	// return a fresh access token for the resolved user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "new access token for %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The client posts grant_type=refresh_token and refresh_token=<token>:
	//   curl -d "grant_type=refresh_token&refresh_token=<token>" \
	//     https://app.example.com/oauth/token
	mux.Handle("/oauth/token", p.Authenticate("refresh-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of the refresh-token grant. Unlike the
// cookie-based strategies, this one reads the refresh_token from the request
// body, so the client must send it explicitly. The snippet POSTs a JSON body
// with grant_type and refresh_token to the /oauth/token endpoint and reads the
// new access token from the response. A real single-page app keeps the refresh
// token in memory (or a secure store) and calls this when its access token
// expires. The Content-Type is application/json so the strategy decodes the JSON
// body rather than a form.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <script>
      // Send the stored refresh token in the request body to get a new access token.
      async function refresh(refreshToken) {
        const res = await fetch("/oauth/token", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ grant_type: "refresh_token", refresh_token: refreshToken }),
        });
        return res.ok ? res.text() : Promise.reject(new Error("re-login required"));
      }
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
