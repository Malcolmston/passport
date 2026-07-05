// Package pinterest provides a passport OAuth2 strategy preset for Pinterest,
// porting the passport-pinterest strategy from the Passport.js ecosystem to
// Pinterest's v5 API. It is a thin configuration layer over strategies/oauth2:
// it fills in Pinterest's authorization, token and user-account endpoints so
// callers only supply their client credentials, a redirect URL and a verify
// function.
//
// Use this preset when you want users to sign in with their Pinterest account,
// for example to read boards and pins on their behalf. Pinterest uses fixed,
// global endpoints, so a single New call with your OAuth app ID and secret is
// all that is required.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to https://www.pinterest.com/oauth/, carrying the client
// ID, redirect URI, requested scopes and an opaque state value. Pinterest then
// redirects the browser back to the callback route with a ?code; the strategy
// exchanges that code at the v5 token endpoint for an access token and calls
// /v5/user_account to fetch the profile. Mount one route for the redirect leg
// and one for the callback, both wired to the "pinterest" strategy.
//
// The default scope is "user_accounts:read", the minimum needed to read the
// authenticated user's account. Pinterest scopes are colon-namespaced; request
// additional scopes (for example "boards:read" or "pins:read") by configuring
// them on the underlying oauth2 strategy. The state parameter should be a
// per-session random value used for CSRF protection; the surrounding passport
// session machinery round-trips it. The verify function receives the fetched
// oauth2.Profile and maps it to your application user; returning a nil user
// (with a nil error) rejects the login, while a non-nil error surfaces as an
// authentication error.
//
// Parity note: this preset targets the Pinterest v5 API. The older v1/v3 API
// endpoints used by earlier versions of the Node strategy are intentionally not
// configured here.
package pinterest

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Pinterest. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("pinterest", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.pinterest.com/oauth/",
		TokenURL:     "https://api.pinterest.com/v5/oauth/token",
		UserInfoURL:  "https://api.pinterest.com/v5/user_account",
		Scopes:       []string{"user_accounts:read"},
	}, verify)
}
