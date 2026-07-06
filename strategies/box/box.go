// Package box provides an OAuth2 "Sign in with Box" authentication strategy for the
// passport port. It is the Go equivalent of the passport-box strategy for
// Passport.js and authenticates users against Box's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Box's authorization endpoint (https://account.box.com/api/oauth2/authorize),
// token endpoint (https://api.box.com/oauth2/token) and current-user endpoint (https://api.box.com/2.0/users/me).
//
// Use this strategy when you want visitors to sign in with their existing
// Box account instead of a local username and password. It suits content and file-management integrations that act on behalf of Box users. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Box's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Box redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, GETs the current-user endpoint with the access token, and invokes the verify function
// with the resulting profile.
//
// No scopes are requested by default; Box applies the application's configured scopes, and the current-user endpoint returns the user's id, name and login (email). The oauth2.Profile handed to verify carries the provider name
// ("box"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-box this exchanges an authorization code and loads the Box
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Box's enterprise JWT server auth and refresh tokens are out of scope; only the user-facing authorization-code flow is provided.
package box

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Box. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("box", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://account.box.com/api/oauth2/authorize",
		TokenURL:     "https://api.box.com/oauth2/token",
		UserInfoURL:  "https://api.box.com/2.0/users/me",
		Scopes:       []string{},
	}, verify)
}
