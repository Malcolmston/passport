// Package linear provides an OAuth2 "Sign in with Linear" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Linear's authorization endpoint (https://linear.app/oauth/authorize), token endpoint
// (https://api.linear.app/oauth/token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Linear with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. This provider exposes no userinfo endpoint here, so the resulting oauth2.Profile carries only the access token and the verify function is responsible for loading identity via the provider API.
//
// The default configuration requests the default scope "read". A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package linear

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Linear. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("linear", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://linear.app/oauth/authorize",
		TokenURL:     "https://api.linear.app/oauth/token",
		UserInfoURL:  "",
		Scopes:       []string{"read"},
	}, verify)
}
