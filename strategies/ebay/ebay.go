// Package ebay provides an OAuth2 "Sign in with eBay" authentication strategy
// for the passport port. It is a thin preset over the shared strategies/oauth2
// engine, filling in eBay's authorization endpoint (https://auth.ebay.com/oauth2/authorize), token endpoint
// (https://api.ebay.com/identity/v1/oauth2/token) and profile settings so callers only supply their client
// credentials, redirect URL and a verify function.
//
// The flow is the standard OAuth2 authorization-code grant driven by the
// returned *oauth2.Strategy: an initiation request with no ?code= redirects the
// browser to eBay with the client ID, redirect URI, requested scopes and
// optional state; the callback carries a ?code= that is exchanged for an access
// token at the token endpoint. After the exchange the strategy GETs https://apiz.ebay.com/commerce/identity/v1/user/ with the access token and hands the decoded profile to verify.
//
// The default configuration requests no scopes by default. A verify function that returns
// a nil user with a nil error is treated as an authentication failure, while a
// non-nil error surfaces as an internal server error. Because it wraps the
// generic OAuth2 strategy, everything the base engine supports — a custom HTTP
// client, state pass-through and the verify contract — is available here too.
package ebay

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for eBay. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("ebay", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.ebay.com/oauth2/authorize",
		TokenURL:     "https://api.ebay.com/identity/v1/oauth2/token",
		UserInfoURL:  "https://apiz.ebay.com/commerce/identity/v1/user/",
		Scopes:       nil,
	}, verify)
}
