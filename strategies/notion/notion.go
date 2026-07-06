// Package notion provides a passport OAuth2 strategy preset for Notion, the
// connected-workspace app. It is a thin wrapper over strategies/oauth2 that
// presets Notion's v1 authorization, token, and users endpoints, and it ports
// passport-notion. New returns a *oauth2.Strategy, so the full OAuth2 base API
// and its documented semantics apply here unchanged.
//
// Use this package to let users connect or log in with their Notion account,
// typically as the first step of an integration that will call the Notion API on
// their behalf. Create a public integration in Notion's developer settings, then
// call New with the OAuth client ID, client secret, and the redirect URI you
// registered, plus a verify function that maps the result to your application
// user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to Notion's
// authorize endpoint (https://api.notion.com/v1/oauth/authorize), and Notion
// redirects back to your callback with a code that is exchanged at
// https://api.notion.com/v1/oauth/token and used to fetch the bot user from
// https://api.notion.com/v1/users/me.
//
// Notion's OAuth has no scopes (access is governed by the pages and databases the
// user shares during the consent step), so the default scope list is empty. The
// Notion API is versioned and requires a "Notion-Version" request header on data
// calls; the token response itself also returns useful fields such as
// "workspace_id" and "bot_id", which you can read from Profile.Raw in your verify
// function. As with every OAuth2 strategy here, "state" is passed through for
// CSRF protection but owned by the surrounding passport middleware, and PKCE is
// not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-notion, this port exposes the raw response on Profile.Raw and leaves
// profile normalization to your verify function.
package notion

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Notion. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("notion", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.notion.com/v1/oauth/authorize",
		TokenURL:     "https://api.notion.com/v1/oauth/token",
		UserInfoURL:  "https://api.notion.com/v1/users/me",
		Scopes:       []string{},
	}, verify)
}
