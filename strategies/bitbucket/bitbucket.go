// Package bitbucket provides an OAuth2 "Sign in with Bitbucket" authentication strategy for the
// passport port. It is the Go equivalent of the passport-bitbucket-oauth2 strategy for
// Passport.js and authenticates users against Bitbucket's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Bitbucket's authorization endpoint (https://bitbucket.org/site/oauth2/authorize),
// token endpoint (https://bitbucket.org/site/oauth2/access_token) and current-user endpoint (https://api.bitbucket.org/2.0/user).
//
// Use this strategy when you want visitors to sign in with their existing
// Bitbucket account instead of a local username and password. It suits developer tools and CI integrations that act on behalf of Bitbucket users. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Bitbucket's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Bitbucket redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the current-user endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// The default scope is "account", which grants read access to the user's account (username, display name and uuid). Bitbucket does not include the email in that response, so a caller who needs it must request the "email" scope and call the separate emails endpoint. The oauth2.Profile handed to verify carries the provider name
// ("bitbucket"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-bitbucket-oauth2 this exchanges an authorization code and loads the Bitbucket
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Refresh tokens and Bitbucket's app-password flow are out of scope.
package bitbucket

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Bitbucket. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("bitbucket", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://bitbucket.org/site/oauth2/authorize",
		TokenURL:     "https://bitbucket.org/site/oauth2/access_token",
		UserInfoURL:  "https://api.bitbucket.org/2.0/user",
		Scopes:       []string{"account"},
	}, verify)
}
