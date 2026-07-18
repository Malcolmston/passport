// Package pipedrive provides an OAuth2 "Sign in with Pipedrive" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Pipedrive's authorization endpoint (https://oauth.pipedrive.com/oauth/authorize), token endpoint
// (https://oauth.pipedrive.com/oauth/token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Pipedrive with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://api.pipedrive.com/v1/users/me with the access token and hands the decoded profile to verify.
//
// The default configuration requests no scopes by default. A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package pipedrive

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Pipedrive. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("pipedrive", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://oauth.pipedrive.com/oauth/authorize",
		TokenURL:     "https://oauth.pipedrive.com/oauth/token",
		UserInfoURL:  "https://api.pipedrive.com/v1/users/me",
		Scopes:       nil,
	}, verify)
}
