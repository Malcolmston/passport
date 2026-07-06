// Package meetup provides a passport OAuth2 strategy preset for Meetup, the
// group-and-event platform. It is a thin wrapper over strategies/oauth2 that
// presets Meetup's authorization and token endpoints, and it ports
// passport-meetup-oauth2. New returns a *oauth2.Strategy, so the full OAuth2 base
// API and its documented semantics apply here unchanged.
//
// Use this package to let users log in with their Meetup account. Register an
// OAuth consumer in the Meetup API settings, then call New with the client (key)
// ID, client secret, and the redirect URL you registered, plus a verify function
// that maps the result to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Meetup's
// authorize endpoint (https://secure.meetup.com/oauth2/authorize), and Meetup
// redirects back to your callback with a code that is exchanged for an access
// token at https://secure.meetup.com/oauth2/access.
//
// This preset configures no userinfo endpoint, because Meetup exposes the
// authenticated member through its GraphQL API rather than a simple userinfo URL.
// As a result FetchUserInfo returns an empty map and Profile.ID is empty; the
// Profile carries only the provider name and the access token. To identify the
// user, query the Meetup API in your verify function using Profile.AccessToken.
// No scopes are requested by default, and "state" is passed through for CSRF
// protection but owned by the surrounding passport middleware.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-meetup-oauth2, this port stops at the token exchange and leaves
// profile fetching to your verify function.
package meetup

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Meetup.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("meetup", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://secure.meetup.com/oauth2/authorize",
		TokenURL:     "https://secure.meetup.com/oauth2/access",
	}, verify)
}
