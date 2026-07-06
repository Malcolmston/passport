// Package stripe provides a Passport strategy preset for signing users in with
// Stripe using OAuth 2.0. It is the Go port of the passport-stripe strategy from the
// Passport.js ecosystem, and is a thin configuration wrapper over
// strategies/oauth2 that hard-codes Stripe's authorization and token endpoints
// so that callers only supply their client credentials and a verify callback.
//
// Reach for this package when you want a "Sign in with Stripe" button in a
// net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
// Stripe is a payments platform, and this flow uses Stripe Connect to link a Stripe account. Because it delegates to strategies/oauth2, it behaves identically to
// every other provider preset in this library, so switching identity providers
// is close to a one-line change.
//
// Authentication is the standard OAuth 2.0 authorization-code flow split across
// two routes. The login route calls Authenticate, which issues a 302 redirect
// to Stripe's authorization endpoint carrying the client id, the requested
// scopes, the registered callback URL, and an opaque single-use state value for
// CSRF protection. After the user consents, Stripe redirects back to the
// callback route with an authorization code; the strategy exchanges that code
// at the token endpoint, and then invokes the verify callback.
//
// The verify callback receives an oauth2.Profile and returns the application
// user to log in, or a nil user to reject the login. The redirect URL passed to
// New must exactly match one registered in your Stripe application settings, or
// the callback will be refused by the provider. The requested scopes default to read_only, which determine what the resulting access token can read. The state
// parameter is generated and validated automatically, so a missing or mismatched
// state fails the callback. This uses Stripe Connect's OAuth flow and exposes no userinfo endpoint, so the profile carries the connected account id rather than a personal profile.
//
// Parity with the Node original is limited to endpoint configuration and the
// verify-callback shape: as with passport-stripe, you register the strategy, expose a
// login route and a callback route, and map the provider profile to a user.
// Profile field population depends on Stripe's response and this library's
// oauth2.Profile mapping, which may normalize fewer fields than the Node
// strategy's provider-specific profile parser.
package stripe

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Stripe. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("stripe", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.stripe.com/oauth/authorize",
		TokenURL:     "https://connect.stripe.com/oauth/token",
		UserInfoURL:  "",
		Scopes:       []string{"read_only"},
	}, verify)
}
