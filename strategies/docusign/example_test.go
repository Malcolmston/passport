package docusign_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/docusign"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// ExampleNew shows the full server-side wiring for the DocuSign OAuth2 strategy.
// It registers the strategy with a passport instance, supplying a verify func
// that maps the fetched provider profile to your application's user (returning a
// nil user rejects the login). It then mounts two routes: an initiation route
// that redirects the browser to DocuSign's authorization endpoint, and a callback
// route that DocuSign redirects back to with an authorization code. On the
// callback the strategy exchanges the code for an access token, fetches the
// /oauth/userinfo profile, and runs the verify func before the success handler
// runs. Finally it wraps the mux with passport's Initialize and Session
// middleware so the authenticated user is persisted across requests.
func ExampleNew() {
	p := passport.New()

	// Register the strategy. The verify func maps the provider profile (the sub
	// claim plus account info in the raw map) to your application user; return a
	// nil user to reject the login.
	p.Use(docusign.New(
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/auth/docusign/callback",
		func(profile oauth2.Profile) (user any, err error) {
			return profile.ID, nil
		},
	))

	mux := http.NewServeMux()
	// Redirect the browser to the provider to begin authorization.
	mux.Handle("/auth/docusign", p.Authenticate("docusign")(nil))
	// The provider redirects back here; the handler runs on success.
	mux.Handle("/auth/docusign/callback", p.Authenticate("docusign")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	// Install passport for every request, then serve.
	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
}

// Example_frontend shows the browser-facing half of the DocuSign login flow. It
// serves a minimal HTML login page whose only interactive element is a "Sign in
// with DocuSign" anchor pointing at the /auth/docusign initiation route wired up
// in ExampleNew. The browser never sees the client secret or handles tokens:
// clicking the link simply navigates to your server, which issues the OAuth2
// redirect to DocuSign. After the user authorizes the application, DocuSign
// returns them to the callback route and the session is established. Serve this
// page from any public, unauthenticated route such as your site's login screen.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/docusign">Sign in with DocuSign</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
