// Package heroku provides a passport authentication strategy for signing users
// in with their Heroku account over OAuth 2.0. It is a thin preset around the
// shared strategies/oauth2 engine, wiring in Heroku's authorization, token, and
// userinfo endpoints so callers only supply their client credentials, a redirect
// URL, and a verify function. It ports the Node passport-heroku strategy to this
// standard-library-only module.
//
// Reach for this package when your application authenticates people through their
// Heroku identity — for example an internal tool or add-on that acts on behalf of
// a Heroku user — using the familiar Passport-style register-a-strategy-then-
// mount-two-routes flow. Because it delegates to strategies/oauth2, everything
// documented on that engine — the Profile shape, the VerifyFunc contract, and the
// redirect/callback handling — applies here unchanged; this package's only job is
// to fill in the Heroku-specific configuration.
//
// The flow is the standard authorization-code grant. A request without a "code"
// query parameter is treated as the start of login, so the strategy redirects the
// browser to Heroku's authorization endpoint
// (https://id.heroku.com/oauth/authorize). Heroku authenticates the user and
// redirects back to your RedirectURL with a "code"; the strategy then exchanges
// that code for an access token at the token endpoint
// (https://id.heroku.com/oauth/token) and GETs the account endpoint
// (https://api.heroku.com/account) with the bearer token to build the Profile
// that is handed to your verify function.
//
// This preset requests the "identity" scope by default, which grants read access
// to the authenticated user's basic account information — enough to identify them
// without broader platform permissions. The "state" parameter is forwarded
// opaquely for CSRF protection but is neither generated nor validated by this
// engine — that is the caller's responsibility — and there is no PKCE in the base
// engine. Profile.ID is populated best-effort from the account payload (Heroku
// returns an "id" field) via the engine's common id/sub/user_id/uuid/login
// lookup.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to establish
// the session, return a nil user with a nil error to reject the login (reported
// as an HTTP 401 failure), and return a non-nil error for an internal failure.
// Compared with the Node passport-heroku original, this port keeps the same
// provider endpoints, default scope, and redirect/callback semantics while
// relying on the smaller shared engine, so it has no built-in state store, no
// PKCE, and no automatic token refresh.
package heroku

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Heroku. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("heroku", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://id.heroku.com/oauth/authorize",
		TokenURL:     "https://id.heroku.com/oauth/token",
		UserInfoURL:  "https://api.heroku.com/account",
		Scopes:       []string{"identity"},
	}, verify)
}
