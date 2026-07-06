// Package imgur provides a passport authentication strategy for signing users in
// with their Imgur account over OAuth 2.0. It is a thin preset around the shared
// strategies/oauth2 engine, wiring in Imgur's authorization, token, and userinfo
// endpoints so callers only supply their client credentials, a redirect URL, and
// a verify function. It ports the Node passport-imgur strategy to this
// standard-library-only module.
//
// Reach for this package when your application lets people authenticate with
// their Imgur account — for example to act on their images or albums — using the
// familiar Passport-style register-a-strategy-then-mount-two-routes flow. Because
// it delegates to strategies/oauth2, the Profile shape, the VerifyFunc contract,
// and the redirect/callback handling all apply here unchanged; this package's
// only job is to fill in the Imgur-specific configuration.
//
// The flow is the standard authorization-code grant. A request without a "code"
// query parameter is treated as the start of login, so the strategy redirects the
// browser to Imgur's authorization endpoint
// (https://api.imgur.com/oauth2/authorize). Imgur authenticates the user and
// redirects back to your RedirectURL with a "code"; the strategy then exchanges
// that code for an access token at the token endpoint
// (https://api.imgur.com/oauth2/token) and GETs the account endpoint
// (https://api.imgur.com/3/account/me) with the bearer token to build the Profile
// that is handed to your verify function.
//
// Imgur requests no default scopes — its OAuth2 access is governed by the
// application's registration rather than per-request scope strings. The "state"
// parameter is forwarded opaquely for CSRF protection but is neither generated
// nor validated by this engine — that is the caller's responsibility — and there
// is no PKCE in the base engine. Profile.ID is populated best-effort from the
// account payload via the engine's common id/sub/user_id/uuid/login lookup.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to establish
// the session, return a nil user with a nil error to reject the login (reported
// as an HTTP 401 failure), and return a non-nil error for an internal failure.
// Compared with the Node passport-imgur original, this port keeps the same
// provider endpoints and redirect/callback semantics while relying on the smaller
// shared engine, so it has no built-in state store, no PKCE, and no automatic
// token refresh.
package imgur

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Imgur.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("imgur", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.imgur.com/oauth2/authorize",
		TokenURL:     "https://api.imgur.com/oauth2/token",
		UserInfoURL:  "https://api.imgur.com/3/account/me",
	}, verify)
}
