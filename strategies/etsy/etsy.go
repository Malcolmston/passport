// Package etsy provides a passport OAuth2 strategy preset for signing users in
// with their Etsy account through the Etsy Open API v3. It is the Go analogue of
// the Passport.js passport-etsy strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Etsy's www.etsy.com/oauth/connect
// authorization endpoint and the api.etsy.com v3 token endpoint so callers supply
// only their client credentials and a verify function.
//
// Use this strategy when you want "Sign in with Etsy" or need an access token to
// call the Etsy Open API on a seller's or buyer's behalf. No scopes are set by
// default; Etsy requires you to request explicit scopes (for example
// "email_r shops_r transactions_r"), so for real use register a custom
// oauth2.Strategy with the scopes your integration needs.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to Etsy's connect endpoint with your
// client_id (keystring), redirect_uri, response_type=code, and scopes. Etsy
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges the code for an access token. No userinfo endpoint is
// configured, so the resulting oauth2.Profile carries the provider name and
// access token but an empty ID and empty Raw map.
//
// Etsy encodes the numeric user id as the prefix of the access token itself (the
// part before the "." separator), so your VerifyFunc can derive the user id from
// Profile.AccessToken, or call the /v3/application/users/me endpoint with the
// token. Return a non-nil user to establish the session, a nil user with a nil
// error to reject the login (HTTP 401), or a non-nil error for an internal error.
//
// Parity with Passport.js and a critical caveat: Etsy's Open API v3 mandates PKCE
// (a code_challenge on the authorization request and a matching code_verifier on
// the token exchange). The generic oauth2 base does NOT implement PKCE, so this
// preset alone will not complete a live Etsy login; use it as a starting point
// and supply the PKCE parameters through a custom initiation handler and token
// exchange. The strategy registers under the name "etsy".
package etsy

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Etsy.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("etsy", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.etsy.com/oauth/connect",
		TokenURL:     "https://api.etsy.com/v3/public/oauth/token",
	}, verify)
}
