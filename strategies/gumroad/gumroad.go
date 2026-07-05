// Package gumroad provides a passport authentication strategy for signing users
// in with their Gumroad account over OAuth 2.0. It is a thin preset around the
// shared strategies/oauth2 engine, wiring in Gumroad's authorization, token, and
// userinfo endpoints so callers only supply their client credentials, a redirect
// URL, and a verify function. It ports the Node passport-gumroad strategy to this
// standard-library-only module.
//
// Reach for this package when your application lets people authenticate as
// Gumroad creators or customers and you want the familiar Passport-style
// register-a-strategy-then-mount-two-routes flow. Because it delegates to
// strategies/oauth2, everything documented on that engine — the Profile shape,
// the VerifyFunc contract, and the redirect/callback handling — applies here
// unchanged; this package's only job is to fill in the Gumroad-specific
// configuration.
//
// The flow is the standard authorization-code grant. A request without a "code"
// query parameter is treated as the start of login, so the strategy redirects the
// browser to Gumroad's authorization endpoint
// (https://gumroad.com/oauth/authorize). Gumroad authenticates the user and
// redirects back to your RedirectURL with a "code"; the strategy then exchanges
// that code for an access token at the token endpoint
// (https://gumroad.com/oauth/token) and GETs the userinfo endpoint
// (https://api.gumroad.com/v2/user) with the bearer token to build the Profile
// that is handed to your verify function.
//
// Gumroad requests no default scopes, so the token grants whatever access the
// application's OAuth registration was configured for; pass any additional
// permissions through your Gumroad application settings. The "state" parameter is
// forwarded opaquely for CSRF protection but is neither generated nor validated
// by this engine — that is the caller's responsibility — and there is no PKCE in
// the base engine. Profile.ID is populated best-effort from the userinfo payload
// (typically the "id" field returned under Gumroad's "user" object) via the
// engine's common id/sub/user_id/uuid/login lookup.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to establish
// the session, return a nil user with a nil error to reject the login (reported
// as an HTTP 401 failure), and return a non-nil error for an internal failure.
// Compared with the Node passport-gumroad original, this port keeps the same
// provider endpoints and redirect/callback semantics while relying on the smaller
// shared engine, so it has no built-in state store, no PKCE, and no automatic
// token refresh.
package gumroad

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Gumroad.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("gumroad", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://gumroad.com/oauth/authorize",
		TokenURL:     "https://gumroad.com/oauth/token",
		UserInfoURL:  "https://api.gumroad.com/v2/user",
	}, verify)
}
