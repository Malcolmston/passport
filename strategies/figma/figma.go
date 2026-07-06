// Package figma provides a passport OAuth2 strategy preset for signing users in
// with their Figma account. It is the Go port of the Passport.js passport-figma
// strategy and a thin wrapper over the shared strategies/oauth2 engine,
// presetting Figma's www.figma.com/oauth authorization endpoint, the
// api.figma.com token endpoint, and the v1/me userinfo resource so callers supply
// only their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with Figma" or need an access token to
// call the Figma REST API (for example to read a user's files, projects, or
// comments) in a design tool or integration. It requests the "files:read" scope
// by default; Figma currently exposes a limited set of scopes, so add others via
// a custom oauth2.Strategy only as Figma makes them available.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route the
// strategy redirects the browser to Figma's oauth endpoint with your client_id,
// redirect_uri, response_type=code, scopes, and state. Figma authenticates the
// user and redirects back to your callback route with ?code=; the strategy
// exchanges the code for an access token, calls v1/me with the bearer token, and
// builds an oauth2.Profile (Provider "figma", ID from the response's id field,
// the raw JSON map, and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. Important: Figma REQUIRES the state
// parameter on the authorization request, but this port only appends state when
// you pass ?state= to the initiation route and does not generate or validate it
// for you, so always supply a state value (and validate it on the callback) when
// targeting Figma. PKCE is not implemented.
//
// Parity with Passport.js: the strategy registers under the name "figma". Figma's
// v1/me returns id, email, handle, and img_url; the normalized profile is minimal
// (id, raw map, access token), so read the display fields from Profile.Raw inside
// your verify function. Refresh tokens and expiry are parsed by the oauth2 base
// but not persisted for you.
package figma

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Figma. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("figma", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.figma.com/oauth",
		TokenURL:     "https://api.figma.com/v1/oauth/token",
		UserInfoURL:  "https://api.figma.com/v1/me",
		Scopes:       []string{"files:read"},
	}, verify)
}
