package cas_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/cas"
)

// ExampleNew shows the full wiring for the CAS (Central Authentication Service)
// strategy: register it with passport, then mount the login and service-callback
// routes. With no ticket the strategy redirects the browser to the CAS server;
// CAS redirects back to the service URL with a ticket that is validated against
// the server.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the validated CAS username
	// (and any released attributes) to your application user (return a nil user
	// to reject the login).
	p.Use(cas.New(
		cas.Config{
			BaseURL: "https://cas.example.com/cas",
			Service: "https://app.example.com/auth/cas/callback",
		},
		func(username string, attributes map[string]string) (user any, err error) {
			return username, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the CAS server to begin authentication.
	mux.Handle("/auth/cas", p.Authenticate("cas")(nil))
	// CAS redirects back here with a ticket; the handler runs on success.
	mux.Handle("/auth/cas/callback", p.Authenticate("cas")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}
