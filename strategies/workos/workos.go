// Package workos provides a Passport strategy preset for signing users in with
// WorkOS using OAuth 2.0. It is the Go port of the passport-workos strategy from the
// Passport.js ecosystem, and is a thin configuration wrapper over
// strategies/oauth2 that hard-codes WorkOS's authorization and token endpoints
// so that callers only supply their client credentials and a verify callback.
//
// Reach for this package when you want a "Sign in with WorkOS" button in a
// net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
// WorkOS brokers enterprise single sign-on (SAML/OIDC) behind one OAuth 2.0 flow. Because it delegates to strategies/oauth2, it behaves identically to
// every other provider preset in this library, so switching identity providers
// is close to a one-line change.
//
// Authentication is the standard OAuth 2.0 authorization-code flow split across
// two routes. The login route calls Authenticate, which issues a 302 redirect
// to WorkOS's authorization endpoint carrying the client id, the requested
// scopes, the registered callback URL, and an opaque single-use state value for
// CSRF protection. After the user consents, WorkOS redirects back to the
// callback route with an authorization code; the strategy exchanges that code
// at the token endpoint, and then invokes the verify callback.
//
// The verify callback receives an oauth2.Profile and returns the application
// user to log in, or a nil user to reject the login. The redirect URL passed to
// New must exactly match one registered in your WorkOS application settings, or
// the callback will be refused by the provider. No scopes are requested by default, so the token is limited to the provider's baseline access. The state
// parameter is generated and validated automatically, so a missing or mismatched
// state fails the callback. Because WorkOS fronts a company's own identity provider, the party the user actually authenticates with is their employer's IdP, not WorkOS itself.
//
// Parity with the Node original is limited to endpoint configuration and the
// verify-callback shape: as with passport-workos, you register the strategy, expose a
// login route and a callback route, and map the provider profile to a user.
// Profile field population depends on WorkOS's response and this library's
// oauth2.Profile mapping, which may normalize fewer fields than the Node
// strategy's provider-specific profile parser.
package workos

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for WorkOS SSO.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("workos", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.workos.com/sso/authorize",
		TokenURL:     "https://api.workos.com/sso/token",
	}, verify)
}
