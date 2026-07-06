package clientcredentials_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/clientcredentials"
)

// ExampleNew shows the full wiring for the OAuth2 client-credentials strategy,
// used for machine-to-machine authentication. The client sends its id/secret in
// the Authorization header; the verify func validates the pair and returns the
// authenticated client. The strategy registers under the name
// "client-credentials".
//
// A client authenticates like so:
//
//	curl -u CLIENT_ID:CLIENT_SECRET http://localhost:3000/api/data
func ExampleNew() {
	p := passport.New()

	// The verify func validates the client id/secret and returns the
	// authenticated client. Return clientcredentials.ErrInvalidClient (or a nil
	// user) to reject the request.
	p.Use(clientcredentials.New(func(id, secret string) (user any, err error) {
		if id == "CLIENT_ID" && secret == "CLIENT_SECRET" {
			return id, nil
		}
		return nil, clientcredentials.ErrInvalidClient
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, client %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// Client-credentials is stateless: skip session creation on success.
	mux.Handle("/api/data", p.Authenticate("client-credentials", passport.Options{Session: false})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
