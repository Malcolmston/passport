// Package monday provides a passport OAuth2 strategy preset for monday.com, the
// work-management platform. It is a thin wrapper over strategies/oauth2 that
// presets monday.com's authorization and token endpoints, and it ports
// passport-monday. New returns a *oauth2.Strategy, so the full OAuth2 base API
// and its documented semantics apply here unchanged.
//
// Use this package to let users log in or connect with their monday.com account,
// typically as the entry point of an app that will call the monday.com GraphQL
// API on their behalf. Register an app in the monday.com developer center, then
// call New with the client ID, client secret, and the redirect URL you
// registered, plus a verify function that maps the result to your application
// user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to monday.com's
// authorize endpoint (https://auth.monday.com/oauth2/authorize), and monday.com
// redirects back to your callback with a code that is exchanged for an access
// token at https://auth.monday.com/oauth2/token.
//
// This preset configures no userinfo endpoint, because monday.com exposes the
// current user through its GraphQL API rather than a REST userinfo URL.
// FetchUserInfo therefore returns an empty map and Profile.ID is empty; the
// Profile carries only the provider name and the access token. To identify the
// user, issue a "me" GraphQL query from your verify function using
// Profile.AccessToken. No scopes are requested by default, and "state" is passed
// through for CSRF protection but owned by the surrounding passport middleware.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-monday, this port stops at the token exchange and leaves profile
// fetching to your verify function.
package monday

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for monday.com.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("monday", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.monday.com/oauth2/authorize",
		TokenURL:     "https://auth.monday.com/oauth2/token",
	}, verify)
}
