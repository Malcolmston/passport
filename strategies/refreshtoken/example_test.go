package refreshtoken_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/refreshtoken"
)

// ExampleNew shows the full wiring for the OAuth2 refresh-token strategy:
// register it with passport and mount a protected token endpoint that reads the
// refresh_token from the request body.
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
