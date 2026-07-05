// Package docusign provides a passport OAuth2 strategy preset for signing users
// in with their DocuSign account. It is the Go port of the Passport.js
// passport-docusign strategy and a thin wrapper over the shared strategies/oauth2
// engine, presetting DocuSign's production account.docusign.com authorization,
// token, and userinfo endpoints so callers supply only their client credentials
// and a verify function.
//
// Use this strategy when you want "Sign in with DocuSign" or need an access token
// to call the DocuSign eSignature REST API on the user's behalf. It requests the
// "signature" scope by default, which is required to send and manage envelopes;
// add scopes such as "extended" (for a refresh token) or "impersonation" via a
// custom oauth2.Strategy when you need them.
//
// The flow is the OAuth2 Authorization Code Grant. On the initiation route (no
// ?code=) the strategy redirects the browser to DocuSign's authorize endpoint
// with your client_id (integration key), redirect_uri, response_type=code, and
// scopes. DocuSign authenticates the user and redirects back to your callback
// route with ?code=; the strategy exchanges the code for an access token, calls
// the /oauth/userinfo endpoint with the bearer token, and builds an
// oauth2.Profile (Provider "docusign", ID from the sub claim, the raw JSON map,
// and the access token). The userinfo response also lists the accounts and base
// URIs the user can access, which you typically persist for later API calls.
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "docusign" and
// targets the production authentication server. For the developer sandbox use a
// custom oauth2.Strategy pointed at account-d.docusign.com. Refresh tokens
// (available only when you also request the "extended" scope) and token expiry
// are parsed by the oauth2 base but not persisted for you, so store what you need
// from Profile.Raw inside your verify function.
package docusign

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for DocuSign.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("docusign", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://account.docusign.com/oauth/auth",
		TokenURL:     "https://account.docusign.com/oauth/token",
		UserInfoURL:  "https://account.docusign.com/oauth/userinfo",
		Scopes:       []string{"signature"},
	}, verify)
}
