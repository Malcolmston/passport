// Package atlassian provides an OAuth2 "Sign in with Atlassian" authentication strategy for the
// passport port. It is the Go equivalent of the passport-atlassian-oauth2 strategy for
// Passport.js and authenticates users against Atlassian's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Atlassian's authorization endpoint (https://auth.atlassian.com/authorize),
// token endpoint (https://auth.atlassian.com/oauth/token) and accessible-resources me endpoint (https://api.atlassian.com/me).
//
// Use this strategy when you want visitors to sign in with their existing
// Atlassian account instead of a local username and password. It suits apps that integrate with Jira, Confluence or other Atlassian Cloud products. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Atlassian's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Atlassian redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the me endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// The default scope is "read:me", which grants the user's account id, name and email. The oauth2.Profile handed to verify carries the provider name
// ("atlassian"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-atlassian-oauth2 this exchanges an authorization code and loads the Atlassian
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Atlassian's OAuth normally requires an audience=api.atlassian.com parameter (and typically prompt=consent) on the authorization request, plus a separate call to enumerate accessible cloud resources before reaching product APIs; this preset issues the basic identity flow, leaving those extra parameters and resource lookups to be layered on by the caller.
package atlassian

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Atlassian. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("atlassian", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.atlassian.com/authorize",
		TokenURL:     "https://auth.atlassian.com/oauth/token",
		UserInfoURL:  "https://api.atlassian.com/me",
		Scopes:       []string{"read:me"},
	}, verify)
}
