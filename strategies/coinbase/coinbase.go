// Package coinbase provides a passport OAuth2 strategy preset for signing users
// in with their Coinbase account. It is the Go port of the Passport.js
// passport-coinbase strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Coinbase's authorization endpoint
// (login.coinbase.com), token endpoint, and the v2/user userinfo resource so
// callers supply only their client credentials and a verify function.
//
// Use this strategy when you want a "Sign in with Coinbase" login for a
// cryptocurrency or fintech application, or to bootstrap access to a Coinbase
// user's wallet data on their behalf. It requests the "wallet:user:read" scope
// by default, which grants read access to the authenticated user's public
// profile (id, name, avatar). Request additional wallet or transaction scopes by
// registering your own oauth2.Strategy if you need more than identity.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Coinbase's authorize endpoint
// with your client_id, redirect_uri, response_type=code, and scopes. Coinbase
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges that code for an access token, calls v2/user with the
// bearer token, and builds an oauth2.Profile (Provider "coinbase", ID from the
// response, the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login as an
// authentication failure (HTTP 401), or a non-nil error for an internal error.
// State from the initiation request's ?state= parameter is forwarded and echoed
// back for CSRF protection, but this port neither generates nor validates it and
// does not implement PKCE, so add those safeguards in your own initiation handler
// when required.
//
// Parity with Passport.js: the strategy registers under the name "coinbase" and
// mirrors passport-coinbase's default read scope, but the normalized profile is
// intentionally minimal (id, raw map, access token) rather than the structured
// profile object the Node strategy produces. Coinbase wraps its user payload in a
// top-level "data" object, so read richer fields from Profile.Raw["data"] inside
// your verify function; refresh tokens and expiry are parsed by the oauth2 base
// but not persisted for you.
package coinbase

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Coinbase.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("coinbase", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://login.coinbase.com/oauth2/auth",
		TokenURL:     "https://api.coinbase.com/oauth/token",
		UserInfoURL:  "https://api.coinbase.com/v2/user",
		Scopes:       []string{"wallet:user:read"},
	}, verify)
}
