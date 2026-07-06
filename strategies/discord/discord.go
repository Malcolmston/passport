// Package discord provides a passport OAuth2 strategy preset for signing users
// in with their Discord account. It is the Go port of the Passport.js
// passport-discord strategy: a thin wrapper over the shared strategies/oauth2
// engine that presets Discord's authorization, token, and userinfo endpoints
// (the discord.com/api/oauth2 endpoints and the users/@me resource) so callers
// only supply their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with Discord" in a web application:
// user identification, community or bot dashboards, or any product whose
// audience already has Discord accounts. It requests the "identify" and "email"
// scopes by default, which return the user's id, username, avatar, and verified
// email. If you need guilds, connections, or other data, register your own
// oauth2.Strategy with wider scopes instead.
//
// The flow is the standard OAuth2 authorization-code grant. On the initiation
// route there is no ?code= query parameter, so the strategy redirects the
// browser to Discord's authorize endpoint with your client_id, redirect_uri,
// response_type=code, and scopes. After the user approves, Discord redirects
// back to your callback route with ?code=; the strategy exchanges that code for
// an access token at the token endpoint, calls users/@me with the bearer token,
// and builds an oauth2.Profile (Provider "discord", ID from the response, the
// raw JSON map, and the access token).
//
// The Profile is handed to your VerifyFunc, whose contract governs the outcome:
// return a non-nil user to establish the session, return a nil user with a nil
// error to reject the login as an authentication failure (HTTP 401), or return a
// non-nil error to surface an internal error. State is passed through opaquely
// from the initiation request's ?state= parameter for CSRF protection; this port
// neither generates nor validates state for you, and it does not implement PKCE,
// so add those in your own initiation handler if your threat model requires them.
//
// Parity with Passport.js: the strategy name is "discord" and the default scopes
// match a common passport-discord setup, but the normalized profile is
// intentionally minimal (id, raw map, access token) rather than the fully
// structured profile object the Node strategy builds. Refresh tokens and token
// expiry are parsed by the oauth2 base but not persisted here, so persist
// whatever you need out of Profile.Raw inside your verify function.
package discord

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Discord. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("discord", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://discord.com/api/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserInfoURL:  "https://discord.com/api/users/@me",
		Scopes:       []string{"identify", "email"},
	}, verify)
}
