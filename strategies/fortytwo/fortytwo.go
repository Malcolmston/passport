// Package fortytwo provides a passport OAuth2 strategy preset for signing users
// in with their 42 intranet ("intra") account through api.intra.42.fr. It is the
// Go port of the Passport.js passport-42 strategy and a thin wrapper over the
// shared strategies/oauth2 engine, presetting 42's authorization and token
// endpoints and the v2/me userinfo resource so callers supply only their
// application credentials and a verify function.
//
// Use this strategy when you want "Sign in with 42" in a tool for the 42
// coding-school network -- student dashboards, project trackers, or community
// apps whose users all hold 42 intra accounts. It requests the "public" scope by
// default, which returns the user's public profile; request additional scopes
// such as "projects" via a custom oauth2.Strategy if you need more.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to 42's authorize endpoint with your
// client_id (application UID), redirect_uri, response_type=code, and scopes. 42
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges the code for an access token, calls v2/me with the
// bearer token, and builds an oauth2.Profile (Provider "fortytwo", ID from the
// numeric id field, the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you, and
// PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "fortytwo". 42
// returns a rich profile (login, email, campus, cursus, image URLs) that the
// normalized Profile reduces to id plus the raw map, so read the extra fields
// from Profile.Raw inside your verify function. The numeric id is decoded from
// JSON as a number and rendered as its integer string in Profile.ID. Refresh
// tokens and expiry are parsed by the oauth2 base but not persisted for you.
package fortytwo

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for 42 intra.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("fortytwo", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.intra.42.fr/oauth/authorize",
		TokenURL:     "https://api.intra.42.fr/oauth/token",
		UserInfoURL:  "https://api.intra.42.fr/v2/me",
		Scopes:       []string{"public"},
	}, verify)
}
