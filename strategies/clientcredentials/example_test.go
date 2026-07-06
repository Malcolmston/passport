package clientcredentials_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/clientcredentials"
)

// ExampleNew shows the full wiring for the OAuth2 client-credentials strategy,
// used for machine-to-machine authentication with no end user. It registers the
// strategy with a passport instance, supplying a verify func that validates the
// client id/secret pair and returns the authenticated client. The client presents
// its credentials on every request, either as HTTP Basic auth or as client_id and
// client_secret form fields, and the strategy extracts them before calling
// verify. Because the flow is stateless, the protected route is mounted with
// passport.Options{Session: false} so no session cookie is created. The strategy
// registers under the name "client-credentials".
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

// Example_frontend documents that the client-credentials grant is a
// machine-to-machine flow with no user-facing browser page: there is no login
// form and no HTML to serve. Instead the calling service authenticates itself by
// sending its own client id and secret on each request, here via HTTP Basic auth
// on the Authorization header. This example plays the role of that remote client,
// building a request to the protected endpoint from ExampleNew and attaching the
// credentials with Request.SetBasicAuth. In production the id and secret come from
// configuration or a secrets manager, never from a page a human visits. The
// response is whatever the protected handler returns once the strategy validates
// the pair.
func Example_frontend() {
	req, err := http.NewRequest(http.MethodGet, "http://localhost:3000/api/data", nil)
	if err != nil {
		log.Fatal(err)
	}
	// The service presents its own credentials; no user or browser is involved.
	req.SetBasicAuth("CLIENT_ID", "CLIENT_SECRET")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
