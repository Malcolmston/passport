// Package mailchimp provides a passport OAuth2 strategy preset for Mailchimp, the
// email marketing platform. It is a thin wrapper over strategies/oauth2 that
// presets Mailchimp's authorization, token, and metadata endpoints, and it ports
// passport-mailchimp. New returns a *oauth2.Strategy, so the full OAuth2 base API
// and its documented semantics apply here unchanged.
//
// Use this package to let users connect or log in with their Mailchimp account,
// typically as the first step of an integration that will call the Mailchimp
// Marketing API on their behalf. Register an application in Mailchimp, then call
// New with the client ID, client secret, and the redirect URL you registered,
// plus a verify function that maps the returned profile to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Mailchimp's
// authorize endpoint, and Mailchimp redirects back to your callback with a code
// that is exchanged for an access token and used to fetch account metadata from
// https://login.mailchimp.com/oauth2/metadata.
//
// Mailchimp's OAuth2 has no scopes, so the default scope list is empty. The
// metadata response is the closest thing to a userinfo document; it carries the
// account "login" (including the login email) and, importantly, the per-account
// "api_endpoint" (data-center) base URL that subsequent Marketing API calls must
// use. Read those from Profile.Raw in your verify function. As with every OAuth2
// strategy here, "state" is passed through for CSRF protection but owned by the
// surrounding passport middleware, and PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-mailchimp, this port exposes the raw metadata map on Profile.Raw and
// leaves profile normalization to your verify function.
package mailchimp

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Mailchimp. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("mailchimp", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://login.mailchimp.com/oauth2/authorize",
		TokenURL:     "https://login.mailchimp.com/oauth2/token",
		UserInfoURL:  "https://login.mailchimp.com/oauth2/metadata",
		Scopes:       []string{},
	}, verify)
}
