// Package instagram provides a passport authentication strategy for signing users
// in with their Instagram account over OAuth 2.0. It is a thin preset around the
// shared strategies/oauth2 engine, wiring in Instagram's authorization, token, and
// userinfo endpoints so callers only supply their client credentials, a redirect
// URL, and a verify function. It ports the Node passport-instagram strategy to
// this standard-library-only module.
//
// Reach for this package when your application authenticates people through their
// Instagram account — for example to read their basic profile via the Instagram
// Basic Display / Graph API — using the familiar Passport-style register-a-
// strategy-then-mount-two-routes flow. Because it delegates to strategies/oauth2,
// the Profile shape, the VerifyFunc contract, and the redirect/callback handling
// all apply here unchanged; this package's only job is to fill in the
// Instagram-specific configuration.
//
// The flow is the standard authorization-code grant. A request without a "code"
// query parameter is treated as the start of login, so the strategy redirects the
// browser to Instagram's authorization endpoint
// (https://api.instagram.com/oauth/authorize). Instagram authenticates the user
// and redirects back to your RedirectURL with a "code"; the strategy then
// exchanges that code for an access token at the token endpoint
// (https://api.instagram.com/oauth/access_token) and GETs the Graph "me" endpoint
// (https://graph.instagram.com/me) with the bearer token to build the Profile
// that is handed to your verify function.
//
// This preset requests the "user_profile" scope by default, granting access to
// the user's basic profile fields. The "state" parameter is forwarded opaquely
// for CSRF protection but is neither generated nor validated by this engine —
// that is the caller's responsibility — and there is no PKCE in the base engine.
// Profile.ID is populated best-effort from the payload (the Graph API returns an
// "id" field) via the engine's common id/sub/user_id/uuid/login lookup.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to establish
// the session, return a nil user with a nil error to reject the login (reported
// as an HTTP 401 failure), and return a non-nil error for an internal failure.
// Compared with the Node passport-instagram original, this port keeps the same
// provider endpoints, default scope, and redirect/callback semantics while
// relying on the smaller shared engine, so it has no built-in state store, no
// PKCE, and no automatic token refresh.
package instagram

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Instagram. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("instagram", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.instagram.com/oauth/authorize",
		TokenURL:     "https://api.instagram.com/oauth/access_token",
		UserInfoURL:  "https://graph.instagram.com/me",
		Scopes:       []string{"user_profile"},
	}, verify)
}
