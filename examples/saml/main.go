// Command saml demonstrates a SAML 2.0 Service Provider using the Web Browser
// SSO POST binding, end to end, with a bundled mock Identity Provider so the
// flow is runnable without external infrastructure:
//
//	GET  /              login page (SP-initiated: button to start SSO)
//	GET  /sso/login     SP builds an AuthnRequest and redirects to the IdP
//	GET  /idp/sso       mock IdP: authenticates and auto-POSTs a SAMLResponse
//	POST /acs           Assertion Consumer Service — the saml strategy runs here
//
// SECURITY: the saml strategy performs NO signature validation. A production SP
// MUST verify the XML digital signature before trusting the assertion.
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/saml"
)

const (
	acsURL   = "http://localhost:3000/acs"
	idpSSO   = "/idp/sso"
	idpIssue = "alice@example.com" // the mock IdP asserts this NameID
)

const loginPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>SAML SP login</title></head>
<body>
  <h1>Sign in with SSO</h1>
  <p>Status: <strong>%s</strong></p>
  <!-- SP-initiated login: send the browser to the SP's login endpoint. -->
  <form method="GET" action="/sso/login">
    <button type="submit">Log in with SSO</button>
  </form>
</body>
</html>`

// idpAutoPost is the mock IdP's response: an HTML form that auto-submits the
// SAMLResponse to the SP's ACS endpoint (the standard POST-binding pattern).
const idpAutoPost = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Redirecting…</title></head>
<body onload="document.forms[0].submit()">
  <noscript><p>JavaScript is disabled; click to continue.</p></noscript>
  <form method="POST" action="%s">
    <input type="hidden" name="SAMLResponse" value="%s">
    <input type="hidden" name="RelayState" value="%s">
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>`

func samlResponseXML(nameID string) string {
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Assertion><saml:Subject>` +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` +
		nameID +
		`</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`
}

func main() {
	p := passport.New()

	p.Use(saml.New(saml.Options{
		Verify: func(nameID string) (any, error) {
			return map[string]string{"email": nameID}, nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(map[string]string)["email"], nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		return map[string]string{"email": id}, nil
	})

	mux := http.NewServeMux()

	// GET / — login page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		status := "not signed in"
		if u := passport.User(r); u != nil {
			status = "signed in as " + u.(map[string]string)["email"]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, loginPage, status)
	})

	// GET /sso/login — SP-initiated: in a real SP this builds a base64
	// AuthnRequest and redirects to the IdP's SSO URL. Here we redirect to the
	// bundled mock IdP.
	mux.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, idpSSO+"?RelayState=/", http.StatusFound)
	})

	// GET /idp/sso — mock IdP: "authenticate" the user and auto-POST a
	// SAMLResponse back to the SP's ACS endpoint.
	mux.HandleFunc(idpSSO, func(w http.ResponseWriter, r *http.Request) {
		relay := r.URL.Query().Get("RelayState")
		b64 := base64.StdEncoding.EncodeToString([]byte(samlResponseXML(idpIssue)))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, idpAutoPost, acsURL, b64, relay)
	})

	// POST /acs — Assertion Consumer Service; the saml strategy runs here.
	mux.Handle("/acs", p.Authenticate("saml", passport.Options{SuccessRedirect: "/"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
