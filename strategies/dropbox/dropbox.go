// Package dropbox provides a passport OAuth2 strategy preset for signing users in
// with their Dropbox account. It is the Go port of the Passport.js
// passport-dropbox-oauth2 strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Dropbox's www.dropbox.com authorization
// endpoint, the api.dropboxapi.com token endpoint, and the
// users/get_current_account resource so callers supply only their client
// credentials and a verify function.
//
// Use this strategy when you want "Sign in with Dropbox" or need an access token
// to read or write a user's Dropbox files. No scopes are requested by default;
// with scoped Dropbox apps the granted permissions come from your app's
// configuration in the Dropbox App Console, or you can request specific scopes
// (for example "account_info.read") through a custom oauth2.Strategy.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Dropbox's authorize endpoint
// with your client_id (app key), redirect_uri, and response_type=code. Dropbox
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges the code for an access token and attempts to fetch the
// current account, producing an oauth2.Profile (Provider "dropbox", the raw JSON
// map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "dropbox". Two
// Dropbox-specific quirks are worth noting. First, users/get_current_account is
// an RPC endpoint that Dropbox expects as a POST, whereas the generic base issues
// a GET userinfo request, so the automatic profile fetch may not populate on a
// live Dropbox app; in that case call the account API yourself inside the verify
// function using the access token. Second, Dropbox returns the identifier as
// account_id (nested under "name" for the display name), which the generic id
// extraction does not pick up, so read it from Profile.Raw inside your verify
// function.
package dropbox

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Dropbox. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("dropbox", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.dropbox.com/oauth2/authorize",
		TokenURL:     "https://api.dropboxapi.com/oauth2/token",
		UserInfoURL:  "https://api.dropboxapi.com/2/users/get_current_account",
		Scopes:       nil,
	}, verify)
}
