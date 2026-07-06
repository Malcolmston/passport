package querytoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/querytoken"
)

// ExampleNew shows the full wiring for the querytoken strategy. It registers the
// strategy with passport and mounts a route protected by the "query-token" check.
// The Verify func maps a raw token to your application user, returning
// ErrInvalidToken to reject an unknown token. On success the protected handler
// runs with the resolved user available via passport.User. The client supplies
// the token in the configured query parameter (here "token"):
//
//	curl "https://app.example.com/api/me?token=s3cr3t-token"
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The Verify func maps a raw token to your
	// application user; return a nil user (or querytoken.ErrInvalidToken) to
	// reject the request.
	p.Use(querytoken.New(querytoken.Options{
		Param: "token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, querytoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	// A protected handler that reads the authenticated user.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// The strategy name is "query-token" (from Strategy.Name()).
	mux.Handle("/api/me", p.Authenticate("query-token")(protected))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser side of query-parameter token auth. Unlike
// the cookie strategies, this one reads the credential straight from the URL, so
// the client must append it to the request path. The snippet builds the request
// URL with the token in the "token" query parameter and fetches the protected
// route. This pattern fits signed links and callbacks that cannot set an
// Authorization header, but keep in mind the token is visible in the URL. In a
// real app the token would be short-lived and single-use.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <script>
      // Put the token in the "token" query parameter the strategy reads.
      async function callApi(token) {
        const url = "/api/me?token=" + encodeURIComponent(token);
        const res = await fetch(url);
        return res.ok ? res.text() : Promise.reject(new Error("invalid token"));
      }
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
