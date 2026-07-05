// Package foursquare provides a passport OAuth2 authorization-code strategy
// preset for Foursquare. It is a thin wrapper around the shared strategies/oauth2
// engine, pre-configured with Foursquare's authorization and token endpoints, and
// it ports the Node passport-foursquare strategy to Go using only the standard
// library.
//
// Use this package when you want users to sign in to your application with their
// Foursquare account. Call New with your registered OAuth2 client credentials and
// redirect URL, supply an oauth2.VerifyFunc, and register the resulting
// *oauth2.Strategy with passport via Passport.Use. It saves you from hand-wiring
// Foursquare's endpoints onto the generic OAuth2 strategy.
//
// The strategy drives the standard OAuth2 authorization-code flow. When
// Strategy.Authenticate handles a request without a ?code= query parameter, it
// redirects the browser to Foursquare's AuthURL
// (https://foursquare.com/oauth2/authenticate) with response_type=code. Foursquare
// authorizes the user and redirects back to your callback route with a code, which
// the strategy exchanges for an access token at TokenURL
// (https://foursquare.com/oauth2/access_token). The strategy then builds an
// oauth2.Profile and runs your verify func.
//
// Foursquare is an edge case among these presets: it configures no UserInfoURL and
// no default scopes. Because UserInfoURL is empty, the engine performs no userinfo
// request and hands verify a Profile whose Raw map is empty (Provider is
// "foursquare" and AccessToken is populated; ID is derived only if a raw key is
// present, which it will not be here). If you need Foursquare user details, fetch
// them yourself from the Foursquare API using Profile.AccessToken inside verify.
// Your oauth2.VerifyFunc returns (user, err): returning a nil user with a nil error
// rejects the authentication as a failure, while a non-nil error signals an internal
// error. CSRF protection via the state parameter is the caller's responsibility
// (passport threads ?state= through), and this base engine performs no PKCE.
//
// This package aims for behavioral parity with the Node passport-foursquare
// strategy while staying idiomatic Go and dependency-free. The preset endpoints,
// the absence of a userinfo call, and the empty default scope set mirror the
// upstream Passport.js module.
package foursquare

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Foursquare.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("foursquare", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://foursquare.com/oauth2/authenticate",
		TokenURL:     "https://foursquare.com/oauth2/access_token",
	}, verify)
}
