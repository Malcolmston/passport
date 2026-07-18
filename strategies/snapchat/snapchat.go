// Package snapchat provides an OAuth2 "Sign in with Snapchat" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Snapchat's authorization endpoint (https://accounts.snapchat.com/login/oauth2/authorize), token endpoint
// (https://accounts.snapchat.com/login/oauth2/access_token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Snapchat with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://kit.snapchat.com/v1/me with the access token and hands the decoded profile to verify.
//
// The default configuration requests the default scope "user.display_name". A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package snapchat

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Snapchat. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("snapchat", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://accounts.snapchat.com/login/oauth2/authorize",
		TokenURL:     "https://accounts.snapchat.com/login/oauth2/access_token",
		UserInfoURL:  "https://kit.snapchat.com/v1/me",
		Scopes:       []string{"user.display_name"},
	}, verify)
}
