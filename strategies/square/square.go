// Package square provides a Passport strategy preset for signing users in with
// Square using OAuth 2.0. It is the Go port of the passport-square-oauth2 strategy from the
// Passport.js ecosystem, and is a thin configuration wrapper over
// strategies/oauth2 that hard-codes Square's authorization and token endpoints
// so that callers only supply their client credentials and a verify callback.
//
// Reach for this package when you want a "Sign in with Square" button in a
// net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
// Square is a payments and point-of-sale platform. Because it delegates to strategies/oauth2, it behaves identically to
// every other provider preset in this library, so switching identity providers
// is close to a one-line change.
//
// Authentication is the standard OAuth 2.0 authorization-code flow split across
// two routes. The login route calls Authenticate, which issues a 302 redirect
// to Square's authorization endpoint carrying the client id, the requested
// scopes, the registered callback URL, and an opaque single-use state value for
// CSRF protection. After the user consents, Square redirects back to the
// callback route with an authorization code; the strategy exchanges that code
// at the token endpoint, and then invokes the verify callback.
//
// The verify callback receives an oauth2.Profile and returns the application
// user to log in, or a nil user to reject the login. The redirect URL passed to
// New must exactly match one registered in your Square application settings, or
// the callback will be refused by the provider. The requested scopes default to MERCHANT_PROFILE_READ, which determine what the resulting access token can read. The state
// parameter is generated and validated automatically, so a missing or mismatched
// state fails the callback. Square exposes no OpenID userinfo endpoint here, so the profile is built from the token response alone; call the Square API yourself if you need merchant details.
//
// Parity with the Node original is limited to endpoint configuration and the
// verify-callback shape: as with passport-square-oauth2, you register the strategy, expose a
// login route and a callback route, and map the provider profile to a user.
// Profile field population depends on Square's response and this library's
// oauth2.Profile mapping, which may normalize fewer fields than the Node
// strategy's provider-specific profile parser.
package square

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Square. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("square", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.squareup.com/oauth2/authorize",
		TokenURL:     "https://connect.squareup.com/oauth2/token",
		UserInfoURL:  "",
		Scopes:       []string{"MERCHANT_PROFILE_READ"},
	}, verify)
}
