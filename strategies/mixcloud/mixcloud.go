// Package mixcloud provides a passport OAuth2 strategy preset for Mixcloud, the
// audio-streaming platform for DJ mixes and radio shows. It is a thin wrapper
// over strategies/oauth2 that presets Mixcloud's authorization and token
// endpoints, and it ports passport-mixcloud. New returns a *oauth2.Strategy, so
// the full OAuth2 base API and its documented semantics apply here unchanged.
//
// Use this package to let users log in with their Mixcloud account. Register an
// application in the Mixcloud developer settings, then call New with the client
// ID, client secret, and the redirect URL you registered, plus a verify function
// that maps the result to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Mixcloud's
// authorize endpoint (https://www.mixcloud.com/oauth/authorize), and Mixcloud
// redirects back to your callback with a code that is exchanged for an access
// token at https://www.mixcloud.com/oauth/access_token.
//
// This preset configures no userinfo endpoint, so FetchUserInfo returns an empty
// map and Profile.ID is empty; the Profile carries only the provider name and
// the access token. To identify the user, call the Mixcloud API's authenticated
// "me" endpoint from your verify function using Profile.AccessToken. No scopes
// are requested by default, and "state" is passed through for CSRF protection
// but owned by the surrounding passport middleware; PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-mixcloud, this port stops at the token exchange and leaves profile
// fetching to your verify function.
package mixcloud

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Mixcloud.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("mixcloud", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.mixcloud.com/oauth/authorize",
		TokenURL:     "https://www.mixcloud.com/oauth/access_token",
	}, verify)
}
