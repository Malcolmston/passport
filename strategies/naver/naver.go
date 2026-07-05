// Package naver provides a passport OAuth2 strategy preset for Naver, the Korean
// portal's "Naver Login" identity provider. It is a thin wrapper over
// strategies/oauth2 that presets Naver's authorization, token, and userinfo
// endpoints, and it ports passport-naver. New returns a *oauth2.Strategy, so the
// full OAuth2 base API and its documented semantics apply here unchanged.
//
// Use this package to let users log in with their Naver account. Register an
// application in the Naver Developers console, then call New with the client ID,
// client secret, and the callback URL you registered, plus a verify function
// that maps the returned profile to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Naver's
// authorize endpoint (https://nid.naver.com/oauth2.0/authorize), and Naver
// redirects back to your callback with a code that is exchanged for an access
// token and used to fetch the user's profile from
// https://openapi.naver.com/v1/nid/me.
//
// Naver requests no scopes by default; the fields returned are governed by the
// permissions granted to your application. The /nid/me response wraps the profile
// in a "response" object (with the user id under "response.id") rather than at
// the top level, so the base package's id extraction may not populate Profile.ID
// — read it from Profile.Raw in your verify function. As with every OAuth2
// strategy here, "state" is passed through for CSRF protection but owned by the
// surrounding passport middleware, and PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-naver, this port exposes the raw userinfo map on Profile.Raw and
// leaves profile normalization to your verify function.
package naver

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Naver. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("naver", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://nid.naver.com/oauth2.0/authorize",
		TokenURL:     "https://nid.naver.com/oauth2.0/token",
		UserInfoURL:  "https://openapi.naver.com/v1/nid/me",
		Scopes:       []string{},
	}, verify)
}
