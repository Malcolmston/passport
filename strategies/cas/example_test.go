package cas_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/cas"
)

// ExampleNew shows the full backend wiring for the CAS (Central Authentication
// Service) single sign-on strategy. It registers the strategy with the CAS server
// base URL and this application's service URL, plus a VerifyFunc that maps the
// validated CAS username and released attributes to your application user. The
// "/auth/cas" route has no ?ticket, so Authenticate redirects the browser to the
// CAS login page to begin single sign-on. CAS authenticates the user and
// redirects back to "/auth/cas/callback" with a one-time ticket, which the
// strategy validates server-to-server before running verify and, on success,
// invoking the wrapped handler. Returning a nil user from verify, or a ticket
// that fails validation, rejects the login.
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

// Example_frontend serves the browser-facing page that begins CAS single
// sign-on. It is a minimal HTML document with a single "Sign in with CAS" link
// pointing at the "/auth/cas" initiation route wired in ExampleNew. When the
// visitor clicks it the browser navigates to that route, where the strategy
// redirects on to the central CAS login page. After CAS authenticates the user
// and calls back with a ticket, the backend validates it and establishes the
// session, so this page only needs to offer the entry point. If the user already
// has a CAS session from another application, that redirect completes without a
// second prompt.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/cas">Sign in with CAS</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
}
