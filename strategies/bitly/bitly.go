// Package bitly provides an OAuth2 "Sign in with Bitly" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Bitly's authorization endpoint (https://bitly.com/oauth/authorize), token endpoint
// (https://api-ssl.bitly.com/oauth/access_token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Bitly with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://api-ssl.bitly.com/v4/user with the access token and hands the decoded profile to verify.
//
// The default configuration requests no scopes by default. A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package bitly

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Bitly. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("bitly", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://bitly.com/oauth/authorize",
		TokenURL:     "https://api-ssl.bitly.com/oauth/access_token",
		UserInfoURL:  "https://api-ssl.bitly.com/v4/user",
		Scopes:       nil,
	}, verify)
}
