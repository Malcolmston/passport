// Package asana provides an OAuth2 "Sign in with Asana" authentication strategy for the
// passport port. It is the Go equivalent of the passport-asana strategy for
// Passport.js and authenticates users against Asana's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Asana's authorization endpoint (https://app.asana.com/-/oauth_authorize),
// token endpoint (https://app.asana.com/-/oauth_token) and current-user endpoint (https://app.asana.com/api/1.0/users/me).
//
// Use this strategy when you want visitors to sign in with their existing
// Asana account instead of a local username and password. It suits productivity integrations and internal tools that act on behalf of Asana users. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Asana's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Asana redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the current-user endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// No scopes are requested by default, which grants Asana's default identity scope covering the user's name, email and gid. Note that Asana wraps its user object under a top-level "data" key, so those fields appear beneath data in oauth2.Profile.Raw. The oauth2.Profile handed to verify carries the provider name
// ("asana"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-asana this exchanges an authorization code and loads the Asana
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Refresh tokens and Asana's per-workspace scoping are left to the caller.
package asana

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Asana. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("asana", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.asana.com/-/oauth_authorize",
		TokenURL:     "https://app.asana.com/-/oauth_token",
		UserInfoURL:  "https://app.asana.com/api/1.0/users/me",
		Scopes:       []string{},
	}, verify)
}
