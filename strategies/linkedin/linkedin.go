// Package linkedin provides a passport OAuth2 strategy preset for LinkedIn's
// "Sign in with LinkedIn" identity provider. It is a thin wrapper over
// strategies/oauth2 that presets LinkedIn's v2 authorization, token, and profile
// endpoints, and it ports passport-linkedin-oauth2. New returns a
// *oauth2.Strategy, so the full OAuth2 base API and its documented semantics
// apply here unchanged.
//
// Use this package to let users log in with their LinkedIn account. Create an
// application in the LinkedIn developer portal, request the relevant products
// (Sign In with LinkedIn), then call New with the client ID, client secret, and
// the redirect URL you registered, plus a verify function that maps the returned
// profile to your application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to LinkedIn's
// authorization endpoint, and LinkedIn redirects back to your callback with a
// code that is exchanged for an access token and used to fetch the user's
// profile from https://api.linkedin.com/v2/me.
//
// The default scopes are "r_liteprofile" and "r_emailaddress". Note that
// LinkedIn does not return the email address from the /v2/me profile endpoint;
// fetching it requires a separate call to the emailAddress endpoint, which your
// verify function can make using Profile.AccessToken. As with every OAuth2
// strategy here, "state" is passed through for CSRF protection but owned by the
// surrounding passport middleware, and PKCE is not used. LinkedIn returns the
// member id under "id", which the base package uses for Profile.ID.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-linkedin-oauth2, this port exposes the raw userinfo map on
// Profile.Raw and leaves profile normalization to your verify function.
package linkedin

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Linkedin. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("linkedin", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:  "https://api.linkedin.com/v2/me",
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
	}, verify)
}
