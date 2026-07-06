// Package digitalocean provides a passport OAuth2 strategy preset for signing
// users in with their DigitalOcean account. It is the Go port of the Passport.js
// passport-digitalocean strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting DigitalOcean's cloud.digitalocean.com
// authorization and token endpoints and the v2/account userinfo resource so
// callers supply only their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with DigitalOcean" in a developer
// tool, deployment dashboard, or any product that integrates with a user's
// DigitalOcean account. It requests the "read" scope by default, which grants
// read-only access to the account's profile; request "read write" via a custom
// oauth2.Strategy if your application manages the user's resources.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to DigitalOcean's authorize
// endpoint with your client_id, redirect_uri, response_type=code, and scopes.
// DigitalOcean authenticates the user and redirects back to your callback route
// with ?code=; the strategy exchanges the code for an access token, calls
// v2/account with the bearer token, and builds an oauth2.Profile (Provider
// "digitalocean", the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE is not implemented, so add those where your threat model requires them.
//
// Parity with Passport.js: the strategy registers under the name "digitalocean".
// DigitalOcean nests the user under a top-level "account" object (with a uuid
// field) rather than exposing a flat id, so the generic id extraction leaves
// Profile.ID empty; read the identifier from Profile.Raw["account"] inside your
// verify function. Refresh tokens and expiry are parsed by the oauth2 base but
// not persisted for you.
package digitalocean

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for DigitalOcean. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("digitalocean", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://cloud.digitalocean.com/v1/oauth/authorize",
		TokenURL:     "https://cloud.digitalocean.com/v1/oauth/token",
		UserInfoURL:  "https://api.digitalocean.com/v2/account",
		Scopes:       []string{"read"},
	}, verify)
}
