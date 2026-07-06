// Package fitbit provides a passport OAuth2 strategy preset for signing users in
// with their Fitbit account. It is the Go port of the Passport.js
// passport-fitbit-oauth2 strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Fitbit's www.fitbit.com authorization
// endpoint, the api.fitbit.com token endpoint, and the user profile resource so
// callers supply only their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with Fitbit" or need an access token
// to read a user's health and activity data (steps, heart rate, sleep, weight)
// through the Fitbit Web API. It requests the "profile" scope by default; request
// additional scopes such as "activity", "heartrate", or "sleep" through a custom
// oauth2.Strategy, since Fitbit gates each data domain behind its own scope.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Fitbit's authorize endpoint with
// your client_id, redirect_uri, response_type=code, and scopes. Fitbit
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges the code for an access token, requests
// 1/user/-/profile.json with the bearer token, and builds an oauth2.Profile
// (Provider "fitbit", the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE (which Fitbit supports for public clients) is not implemented here.
//
// Parity with Passport.js: the strategy registers under the name "fitbit". Two
// Fitbit-specific details matter. First, Fitbit's token endpoint expects the
// client to authenticate with HTTP Basic (client_id:client_secret in the
// Authorization header), whereas the generic base sends those credentials in the
// form body; if your Fitbit app rejects the exchange, use a custom strategy that
// sets the Basic header. Second, the profile response nests the user under a
// top-level "user" object (with an encodedId field), so the generic id extraction
// leaves Profile.ID empty -- read the id from Profile.Raw["user"] inside your
// verify function.
package fitbit

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Fitbit. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("fitbit", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.fitbit.com/oauth2/authorize",
		TokenURL:     "https://api.fitbit.com/oauth2/token",
		UserInfoURL:  "https://api.fitbit.com/1/user/-/profile.json",
		Scopes:       []string{"profile"},
	}, verify)
}
