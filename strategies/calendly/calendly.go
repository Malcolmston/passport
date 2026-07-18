// Package calendly provides an OAuth2 "Sign in with Calendly" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in Calendly's authorization endpoint (https://auth.calendly.com/oauth/authorize), token endpoint
// (https://auth.calendly.com/oauth/token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to Calendly with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://api.calendly.com/users/me with the access token and hands the decoded profile to verify.
//
// The default configuration requests the default scope "default". A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package calendly

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Calendly. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("calendly", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.calendly.com/oauth/authorize",
		TokenURL:     "https://auth.calendly.com/oauth/token",
		UserInfoURL:  "https://api.calendly.com/users/me",
		Scopes:       []string{"default"},
	}, verify)
}
