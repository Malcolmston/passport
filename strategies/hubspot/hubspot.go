// Package hubspot provides a passport authentication strategy for signing users
// in with their HubSpot account over OAuth 2.0. It is a thin preset around the
// shared strategies/oauth2 engine, wiring in HubSpot's authorization and token
// endpoints so callers only supply their client credentials, a redirect URL, and
// a verify function. It ports the Node passport-hubspot strategy to this
// standard-library-only module.
//
// Reach for this package when your application connects to a user's HubSpot
// account — for example an integration that reads or writes CRM data on their
// behalf — using the familiar Passport-style register-a-strategy-then-mount-two-
// routes flow. Because it delegates to strategies/oauth2, the Profile shape, the
// VerifyFunc contract, and the redirect/callback handling all apply here
// unchanged; this package's only job is to fill in the HubSpot-specific
// configuration.
//
// The flow is the standard authorization-code grant. A request without a "code"
// query parameter is treated as the start of login, so the strategy redirects the
// browser to HubSpot's authorization endpoint
// (https://app.hubspot.com/oauth/authorize). HubSpot authenticates the user and
// redirects back to your RedirectURL with a "code"; the strategy then exchanges
// that code for an access token at the token endpoint
// (https://api.hubapi.com/oauth/v1/token) and builds the Profile that is handed
// to your verify function.
//
// HubSpot is a notable edge case: this preset leaves the userinfo endpoint EMPTY
// (""). The shared engine therefore skips the userinfo request entirely, so the
// Profile.Raw map is empty and Profile.ID is blank. Your verify function must
// rely on Profile.AccessToken instead — for instance by calling HubSpot's token-
// info or account-detail API yourself to resolve the user, or by simply keying
// the session off the token. The preset requests the "oauth" scope by default;
// the "state" parameter is forwarded opaquely for CSRF protection but is neither
// generated nor validated by this engine, and there is no PKCE in the base
// engine.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to establish
// the session, return a nil user with a nil error to reject the login (reported
// as an HTTP 401 failure), and return a non-nil error for an internal failure.
// Compared with the Node passport-hubspot original, this port keeps the same
// provider endpoints, default scope, and redirect/callback semantics — including
// the absence of a userinfo call — while relying on the smaller shared engine, so
// it has no built-in state store, no PKCE, and no automatic token refresh.
package hubspot

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for HubSpot. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("hubspot", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.hubspot.com/oauth/authorize",
		TokenURL:     "https://api.hubapi.com/oauth/v1/token",
		UserInfoURL:  "",
		Scopes:       []string{"oauth"},
	}, verify)
}
