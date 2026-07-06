// Package clickup provides an OAuth2 "Sign in with ClickUp" authentication strategy for the
// passport port. It is the Go equivalent of the passport-clickup strategy for
// Passport.js and authenticates users against ClickUp's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting ClickUp's authorization endpoint (https://app.clickup.com/api),
// token endpoint (https://api.clickup.com/api/v2/oauth/token) and current-user endpoint (https://api.clickup.com/api/v2/user).
//
// Use this strategy when you want visitors to sign in with their existing
// ClickUp account instead of a local username and password. It suits task-management integrations and internal tools that act on behalf of ClickUp users. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to ClickUp's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, ClickUp redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the current-user endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// ClickUp does not use OAuth scopes, so none are requested; the token can read the authorizing user, whose fields the endpoint returns under a top-level "user" key. The oauth2.Profile handed to verify carries the provider name
// ("clickup"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-clickup this exchanges an authorization code and loads the ClickUp
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// ClickUp does not issue refresh tokens, so access tokens are long-lived until the user revokes them.
package clickup

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for ClickUp.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("clickup", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.clickup.com/api",
		TokenURL:     "https://api.clickup.com/api/v2/oauth/token",
		UserInfoURL:  "https://api.clickup.com/api/v2/user",
	}, verify)
}
