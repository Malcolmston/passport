// Package bungie provides an OAuth2 "Sign in with Bungie" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Bungie's authorization endpoint (https://www.bungie.net/en/OAuth/Authorize), token endpoint
// (https://www.bungie.net/Platform/App/OAuth/Token/) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Bungie with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. This provider exposes no userinfo endpoint here, so the resulting oauth2.Profile carries only the access token and the verify function is responsible for loading identity via the provider API.
//
// The default configuration requests no scopes by default. A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package bungie

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Bungie. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("bungie", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.bungie.net/en/OAuth/Authorize",
		TokenURL:     "https://www.bungie.net/Platform/App/OAuth/Token/",
		UserInfoURL:  "",
		Scopes:       nil,
	}, verify)
}
