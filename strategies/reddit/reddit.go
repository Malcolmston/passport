// Package reddit provides a passport OAuth2 strategy preset for the Reddit
// identity provider, porting the passport-reddit strategy from the Passport.js
// ecosystem. It is a thin configuration layer over strategies/oauth2: it fills
// in Reddit's public authorization, token and userinfo endpoints so callers only
// supply their client credentials, a redirect URL and a verify function.
//
// Use this preset when you want users to sign in with their Reddit account.
// Reddit uses fixed, global endpoints, so a single New call with your OAuth app
// ID and secret is all that is required.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to https://www.reddit.com/api/v1/authorize, carrying the
// client ID, redirect URI, requested scopes and an opaque state value. Reddit
// then redirects the browser back to the callback route with a ?code; the
// strategy exchanges that code at /api/v1/access_token for an access token and
// calls https://oauth.reddit.com/api/v1/me to fetch the profile. Mount one route
// for the redirect leg and one for the callback, both wired to the "reddit"
// strategy.
//
// The default scope is "identity", which grants read access to the account and
// its preferences. The state parameter should be a per-session random value used
// for CSRF protection; the surrounding passport session machinery round-trips
// it. The verify function receives the fetched oauth2.Profile and maps it to your
// application user; returning a nil user (with a nil error) rejects the login,
// while a non-nil error surfaces as an authentication error.
//
// Parity note: Reddit's API requires a descriptive, unique User-Agent header and
// treats "duration=permanent" as the way to obtain a refresh token. Those
// provider-specific request details are outside this preset, which mirrors the
// Node original by configuring endpoints and the default scope only. Set a
// custom HTTP client on the underlying oauth2 strategy if you need to add
// headers.
package reddit

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Reddit. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("reddit", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.reddit.com/api/v1/authorize",
		TokenURL:     "https://www.reddit.com/api/v1/access_token",
		UserInfoURL:  "https://oauth.reddit.com/api/v1/me",
		Scopes:       []string{"identity"},
	}, verify)
}
