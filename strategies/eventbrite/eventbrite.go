// Package eventbrite provides a passport OAuth2 strategy preset for signing users
// in with their Eventbrite account. It is the Go port of the Passport.js
// passport-eventbrite strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Eventbrite's www.eventbrite.com
// authorization and token endpoints and the v3/users/me userinfo resource so
// callers supply only their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with Eventbrite" or need an access
// token to read a user's events, orders, or organizations through the Eventbrite
// v3 API. Eventbrite does not use granular OAuth scopes -- an access token grants
// the same access the user has -- so no scopes are requested by default.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Eventbrite's authorize endpoint
// with your client_id (API key), redirect_uri, and response_type=code.
// Eventbrite authenticates the user and redirects back to your callback route
// with ?code=; the strategy exchanges the code for an access token, calls
// v3/users/me with the bearer token, and builds an oauth2.Profile (Provider
// "eventbrite", ID from the response, the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "eventbrite" and
// mirrors passport-eventbrite's endpoint layout. Eventbrite returns the user's
// email addresses as a nested array (emails) rather than a single field, so read
// the primary/verified address from Profile.Raw inside your verify function.
// Eventbrite tokens do not expire and no refresh token is issued, so there is
// nothing extra to persist beyond the access token.
package eventbrite

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Eventbrite.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("eventbrite", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.eventbrite.com/oauth/authorize",
		TokenURL:     "https://www.eventbrite.com/oauth/token",
		UserInfoURL:  "https://www.eventbriteapi.com/v3/users/me",
	}, verify)
}
