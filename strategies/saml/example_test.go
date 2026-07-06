package saml_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/saml"
)

// ExampleNew shows the full wiring for a SAML 2.0 Service Provider using the
// Web Browser SSO POST binding. The identity provider POSTs a base64
// "SAMLResponse" form field to the Assertion Consumer Service (ACS) endpoint,
// where the strategy extracts the NameID and maps it to an application user. The
// Verify func turns that NameID into your user object, and SerializeUser and
// DeserializeUser persist it across requests through the passport session. The
// ACS route is registered with a SuccessRedirect so the browser is sent home
// once the assertion is accepted. NOTE: this strategy does NOT verify the XML
// signature, so a production SP must add signature validation before trusting
// the assertion.
func ExampleNew() {
	p := passport.New()

	p.Use(saml.New(saml.Options{
		// Map the asserted NameID (e.g. an email) to your application user.
		Verify: func(nameID string) (any, error) {
			return map[string]string{"email": nameID}, nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(map[string]string)["email"], nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		return map[string]string{"email": id}, nil
	})

	mux := http.NewServeMux()

	// POST /acs — the Assertion Consumer Service the IdP posts back to.
	mux.Handle("/acs", p.Authenticate("saml", passport.Options{SuccessRedirect: "/"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser side that starts SP-initiated SAML SSO.
// Unlike an OAuth2 "sign in" link, SAML login usually begins with a POST to the
// application's own login endpoint (here /login/saml), which builds an
// AuthnRequest and redirects the browser onward to the identity provider. The
// user then authenticates at the IdP, which POSTs a signed SAMLResponse back to
// the Assertion Consumer Service (the /acs route wired in ExampleNew). Because
// of that round-trip through the IdP, the button below only kicks off the flow;
// the browser leaves and returns via the IdP. No client-side JavaScript is
// required.
func Example_frontend() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- POST to the SP login endpoint, which redirects on to the IdP. -->
    <form method="post" action="/login/saml">
      <button type="submit">Sign in with SAML SSO</button>
    </form>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
