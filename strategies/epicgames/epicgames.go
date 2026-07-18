// Package epicgames provides an OAuth2 "Sign in with Epic Games" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Epic Games's authorization endpoint (https://www.epicgames.com/id/authorize), token endpoint
// (https://api.epicgames.dev/epic/oauth/v1/token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Epic Games with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://api.epicgames.dev/epic/oauth/v1/userInfo with the access token and hands the decoded profile to verify.
//
// The default configuration requests the default scope "basic_profile". A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package epicgames

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Epic Games. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("epicgames", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.epicgames.com/id/authorize",
		TokenURL:     "https://api.epicgames.dev/epic/oauth/v1/token",
		UserInfoURL:  "https://api.epicgames.dev/epic/oauth/v1/userInfo",
		Scopes:       []string{"basic_profile"},
	}, verify)
}
