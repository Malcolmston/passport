// Package github provides a passport OAuth2 authorization-code strategy preset
// for the GitHub identity provider. It is a thin wrapper around the shared
// strategies/oauth2 engine, pre-configured with GitHub's public authorization,
// token and userinfo endpoints, and it ports the Node passport-github strategy
// (also known as passport-github2) to Go using only the standard library.
//
// Use this package when you want users to sign in to your application with their
// GitHub account. Call New with your registered OAuth App client credentials and
// redirect URL, supply an oauth2.VerifyFunc, and register the resulting
// *oauth2.Strategy with passport via Passport.Use. It spares you from wiring
// GitHub's endpoints and scopes onto the generic OAuth2 strategy by hand.
//
// The strategy drives the standard OAuth2 authorization-code flow. When
// Strategy.Authenticate handles a request without a ?code= query parameter, it
// redirects the browser to GitHub's AuthURL
// (https://github.com/login/oauth/authorize) with response_type=code. GitHub
// authorizes the user and redirects back to your callback route with a code, which
// the strategy exchanges for an access token at TokenURL
// (https://github.com/login/oauth/access_token). It then GETs the UserInfoURL
// (https://api.github.com/user) with the bearer access token, builds an
// oauth2.Profile, and runs your verify func.
//
// This preset requests the read:user and user:email scopes so the userinfo call
// can read the authenticated user's profile and email. The Profile.ID is derived
// best-effort from common raw keys (for GitHub this is typically "id" or "login"),
// with Provider set to "github", Raw holding the decoded userinfo JSON, and
// AccessToken populated. Your oauth2.VerifyFunc returns (user, err): returning a
// nil user with a nil error rejects the authentication as a failure, while a
// non-nil error signals an internal error. CSRF protection via the state parameter
// is the caller's responsibility (passport threads ?state= through), and this base
// engine performs no PKCE.
//
// This package aims for behavioral parity with the Node passport-github
// (passport-github2) strategy while staying idiomatic Go and dependency-free. The
// preset endpoints and default scopes mirror the upstream Passport.js module.
package github

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Github. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("github", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"read:user", "user:email"},
	}, verify)
}
