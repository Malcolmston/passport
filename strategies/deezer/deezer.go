// Package deezer provides a passport OAuth2 strategy preset for signing users in
// with their Deezer account. It is the Go port of the Passport.js
// passport-deezer strategy and a thin wrapper over the shared strategies/oauth2
// engine, presetting Deezer's connect.deezer.com authorization and token
// endpoints so callers supply only their client credentials and a verify
// function.
//
// Use this strategy when you want a "Sign in with Deezer" login for a music
// application. It requests the "basic_access" scope by default, which grants the
// user's public profile; add scopes such as "email" or "manage_library" by
// registering your own oauth2.Strategy if you need them.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Deezer's auth endpoint with your
// client_id (Deezer calls it app_id), redirect_uri, response_type=code, and
// scopes. Deezer authenticates the user and redirects back to your callback route
// with ?code=; the strategy exchanges that code for an access token. No userinfo
// endpoint is configured, so the resulting oauth2.Profile carries the provider
// name and access token but an empty ID and empty Raw map.
//
// Because no profile is fetched automatically, your VerifyFunc should call the
// Deezer API itself (GET https://api.deezer.com/user/me with the access token)
// to obtain the user's id and details. As always, return a non-nil user to
// establish the session, a nil user with a nil error to reject the login (HTTP
// 401), or a non-nil error for an internal error. State is forwarded from the
// initiation request's ?state= parameter but is not generated or validated for
// you, and PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "deezer". Note
// that Deezer deviates from RFC 6749 -- its token endpoint expects app_id and
// secret parameters and historically returned a form-encoded body rather than
// JSON, which the generic oauth2 base (which posts client_id/client_secret and
// decodes a JSON token response) does not special-case. If your Deezer app
// rejects the standard exchange, wire up a custom strategy that speaks Deezer's
// exact token format.
package deezer

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Deezer.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("deezer", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.deezer.com/oauth/auth.php",
		TokenURL:     "https://connect.deezer.com/oauth/access_token.php",
		Scopes:       []string{"basic_access"},
	}, verify)
}
