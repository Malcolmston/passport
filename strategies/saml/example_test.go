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
// where the strategy extracts the NameID and maps it to an application user.
//
// NOTE: this strategy does NOT verify the XML signature; a production SP must.
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
