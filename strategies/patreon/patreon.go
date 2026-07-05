// Package patreon provides a passport OAuth2 strategy preset for Patreon,
// porting the passport-patreon strategy from the Passport.js ecosystem. It is a
// thin configuration layer over strategies/oauth2: it fills in Patreon's
// authorization, token and identity (userinfo) endpoints so callers only supply
// their client credentials, a redirect URL and a verify function.
//
// Use this preset when you want users to sign in with their Patreon account,
// for example to gate content behind a membership tier. Because Patreon uses
// fixed, global endpoints (unlike tenant-based providers), a single New call
// with your OAuth client ID and secret is all that is required.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to https://www.patreon.com/oauth2/authorize, carrying
// the client ID, redirect URI, requested scopes and an opaque state value.
// Patreon then redirects the browser back to the callback route with a ?code;
// the strategy exchanges that code at the token endpoint for an access token and
// calls the /oauth2/v2/identity endpoint to fetch the profile. Mount one route
// for the redirect leg and one for the callback, both wired to the "patreon"
// strategy.
//
// The default scope is "identity", which grants read access to the user's
// account. The state parameter should be a per-session random value used for
// CSRF protection; the surrounding passport session machinery round-trips it.
// The verify function receives the fetched oauth2.Profile and maps it to your
// application user; returning a nil user (with a nil error) rejects the login,
// while a non-nil error surfaces as an authentication error.
//
// Parity note: this preset mirrors the endpoint and default-scope configuration
// of the Node passport-patreon strategy. Provider-specific profile shaping (for
// example, requesting extended member fields via Patreon's include/fields query
// parameters) is left to the caller and can be layered on in the verify
// function.
package patreon

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Patreon. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("patreon", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.patreon.com/oauth2/authorize",
		TokenURL:     "https://api.patreon.com/oauth2/token",
		UserInfoURL:  "https://api.patreon.com/oauth2/v2/identity",
		Scopes:       []string{"identity"},
	}, verify)
}
