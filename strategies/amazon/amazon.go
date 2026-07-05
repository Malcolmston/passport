// Package amazon provides an OAuth2 "Login with Amazon" authentication strategy for the
// passport port. It is the Go equivalent of the passport-amazon strategy for
// Passport.js and authenticates users against Amazon's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Amazon's authorization endpoint (https://www.amazon.com/ap/oa),
// token endpoint (https://api.amazon.com/auth/o2/token) and profile endpoint (https://api.amazon.com/user/profile).
//
// Use this strategy when you want visitors to sign in with their existing
// Amazon account instead of a local username and password. It suits consumer applications that already integrate with Amazon services or simply want to offer Amazon as a social-login option. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Amazon's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Amazon redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the profile endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// The default scope is "profile", which grants the user's name, email and Amazon user id. The oauth2.Profile handed to verify carries the provider name
// ("amazon"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-amazon this exchanges an authorization code and loads the Amazon
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Refresh-token rotation and Amazon's device grant are out of scope; only the interactive authorization-code flow is provided.
package amazon

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Amazon. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("amazon", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.amazon.com/ap/oa",
		TokenURL:     "https://api.amazon.com/auth/o2/token",
		UserInfoURL:  "https://api.amazon.com/user/profile",
		Scopes:       []string{"profile"},
	}, verify)
}
