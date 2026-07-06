// Package google provides a passport OAuth2 authorization-code strategy preset
// for the Google identity provider. It is a thin wrapper around the shared
// strategies/oauth2 engine, pre-configured with Google's public authorization,
// token and OpenID Connect userinfo endpoints, and it ports the Node
// passport-google-oauth20 strategy to Go using only the standard library.
//
// Use this package when you want users to sign in to your application with their
// Google account. Call New with your Google Cloud OAuth client credentials and
// redirect URL, supply an oauth2.VerifyFunc, and register the resulting
// *oauth2.Strategy with passport via Passport.Use. It spares you from wiring
// Google's endpoints and scopes onto the generic OAuth2 strategy by hand.
//
// The strategy drives the standard OAuth2 authorization-code flow. When
// Strategy.Authenticate handles a request without a ?code= query parameter, it
// redirects the browser to Google's AuthURL
// (https://accounts.google.com/o/oauth2/v2/auth) with response_type=code. Google
// authorizes the user and redirects back to your callback route with a code, which
// the strategy exchanges for an access token at TokenURL
// (https://oauth2.googleapis.com/token). It then GETs the UserInfoURL
// (https://openidconnect.googleapis.com/v1/userinfo) with the bearer access token,
// builds an oauth2.Profile, and runs your verify func.
//
// This preset requests the openid, email and profile scopes so the OpenID Connect
// userinfo call returns the user's stable subject identifier and basic profile.
// The Profile.ID is derived best-effort from common raw keys (for Google this is
// the "sub" claim), with Provider set to "google", Raw holding the decoded userinfo
// JSON, and AccessToken populated. Your oauth2.VerifyFunc returns (user, err):
// returning a nil user with a nil error rejects the authentication as a failure,
// while a non-nil error signals an internal error. CSRF protection via the state
// parameter is the caller's responsibility (passport threads ?state= through), and
// this base engine performs no PKCE.
//
// This package aims for behavioral parity with the Node passport-google-oauth20
// strategy while staying idiomatic Go and dependency-free. The preset endpoints and
// default scopes mirror the upstream Passport.js module.
package google

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Google. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("google", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
