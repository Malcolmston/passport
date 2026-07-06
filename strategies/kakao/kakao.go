// Package kakao provides a passport OAuth2 strategy preset for Kakao, the Korean
// "Sign in with Kakao" identity provider. It is a thin wrapper over
// strategies/oauth2 that presets Kakao's authorization, token, and userinfo
// endpoints, and it ports passport-kakao from the Node ecosystem. New returns a
// *oauth2.Strategy, so the full OAuth2 base API and its documented semantics
// apply here unchanged.
//
// Use this package to let users log in with their Kakao account. Register a
// Kakao application in the Kakao Developers console, then call New with the
// application's REST API key as the client ID, its client secret, and the
// redirect URL you registered, plus a verify function that maps the returned
// profile to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Kakao's
// authorize endpoint, and Kakao redirects back to your callback with a code that
// is exchanged for an access token and used to fetch the user's profile from
// https://kapi.kakao.com/v2/user/me.
//
// The default scopes are "profile_nickname" and "account_email"; email in
// particular must be enabled and consented for your Kakao app or it will be
// absent from the profile. As with all OAuth2 strategies in this port, the
// "state" parameter is passed through for CSRF protection but is owned by the
// surrounding passport middleware, and PKCE is not used. Kakao returns the user
// id under "id", which the base package uses to populate Profile.ID.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-kakao, this port exposes the raw userinfo map on Profile.Raw and
// leaves richer profile normalization to your verify function.
package kakao

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Kakao. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("kakao", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://kauth.kakao.com/oauth/authorize",
		TokenURL:     "https://kauth.kakao.com/oauth/token",
		UserInfoURL:  "https://kapi.kakao.com/v2/user/me",
		Scopes:       []string{"profile_nickname", "account_email"},
	}, verify)
}
