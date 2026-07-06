// Package zendesk provides a Passport strategy preset for signing users in with
// Zendesk using OAuth 2.0. It is the Go port of the passport-zendesk strategy from the
// Passport.js ecosystem, and is a thin configuration wrapper over
// strategies/oauth2 that hard-codes Zendesk's authorization and token endpoints
// so that callers only supply their client credentials and a verify callback.
//
// Reach for this package when you want a "Sign in with Zendesk" button in a
// net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
// Zendesk is a customer-support platform. Because it delegates to strategies/oauth2, it behaves identically to
// every other provider preset in this library, so switching identity providers
// is close to a one-line change.
//
// Authentication is the standard OAuth 2.0 authorization-code flow split across
// two routes. The login route calls Authenticate, which issues a 302 redirect
// to Zendesk's authorization endpoint carrying the client id, the requested
// scopes, the registered callback URL, and an opaque single-use state value for
// CSRF protection. After the user consents, Zendesk redirects back to the
// callback route with an authorization code; the strategy exchanges that code
// at the token endpoint, and then invokes the verify callback.
//
// The verify callback receives an oauth2.Profile and returns the application
// user to log in, or a nil user to reject the login. The redirect URL passed to
// New must exactly match one registered in your Zendesk application settings, or
// the callback will be refused by the provider. The requested scopes default to read, which determine what the resulting access token can read. The state
// parameter is generated and validated automatically, so a missing or mismatched
// state fails the callback. Zendesk is subdomain-based - every account lives at {sub}.zendesk.com - so prefer NewWithDomain to target your real host; New uses a placeholder domain that will not work in production.
//
// Parity with the Node original is limited to endpoint configuration and the
// verify-callback shape: as with passport-zendesk, you register the strategy, expose a
// login route and a callback route, and map the provider profile to a user.
// Profile field population depends on Zendesk's response and this library's
// oauth2.Profile mapping, which may normalize fewer fields than the Node
// strategy's provider-specific profile parser.
package zendesk

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder Zendesk host.
const defaultDomain = "example.zendesk.com"

// New returns an OAuth2 strategy for Zendesk using the placeholder domain.
// Prefer NewWithDomain to target your actual account.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Zendesk host
// (e.g. "your-account.zendesk.com"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("zendesk", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oauth/authorizations/new",
		TokenURL:     base + "/oauth/tokens",
		Scopes:       []string{"read"},
	}, verify)
}
