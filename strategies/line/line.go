// Package line provides a passport OAuth2 strategy preset for LINE, the messaging
// platform's "Log in with LINE" identity provider. It is a thin wrapper over
// strategies/oauth2 that presets LINE's v2.1 authorization, token, and profile
// endpoints, and it ports passport-line. New returns a *oauth2.Strategy, so the
// full OAuth2 base API and its documented semantics apply here unchanged.
//
// Use this package to let users log in with their LINE account. Create a LINE
// Login channel in the LINE Developers console, then call New with the channel
// ID as the client ID, the channel secret, and the callback URL you registered,
// plus a verify function that maps the returned profile to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to LINE's
// authorize endpoint, and LINE redirects back to your callback with a code that
// is exchanged for an access token and used to fetch the user's profile from
// https://api.line.me/v2/profile.
//
// The default scopes are "profile", "openid", and "email"; the "openid" scope
// makes this an OpenID Connect request and "email" requires that email
// permission be granted for your channel or the address will be absent. LINE
// returns the user id under "userId" — the base package's best-effort id
// extraction may not populate Profile.ID from that field, so read it from
// Profile.Raw in your verify function if you need it. As with every OAuth2
// strategy here, "state" is passed through for CSRF protection but owned by the
// surrounding passport middleware, and PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-line, this port exposes the raw userinfo map on Profile.Raw and
// leaves profile normalization and any ID-token handling to your verify function.
package line

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for LINE. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("line", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:     "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:  "https://api.line.me/v2/profile",
		Scopes:       []string{"profile", "openid", "email"},
	}, verify)
}
