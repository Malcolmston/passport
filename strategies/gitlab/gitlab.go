// Package gitlab provides a passport OAuth2 authorization-code strategy preset
// for the GitLab identity provider. It is a thin wrapper around the shared
// strategies/oauth2 engine, pre-configured with GitLab.com's public authorization,
// token and userinfo endpoints, and it ports the Node passport-gitlab2 strategy
// to Go using only the standard library.
//
// Use this package when you want users to sign in to your application with their
// GitLab account. Call New with your registered application's client credentials
// and redirect URL, supply an oauth2.VerifyFunc, and register the resulting
// *oauth2.Strategy with passport via Passport.Use. It spares you from wiring
// GitLab's endpoints and scope onto the generic OAuth2 strategy by hand.
//
// The strategy drives the standard OAuth2 authorization-code flow. When
// Strategy.Authenticate handles a request without a ?code= query parameter, it
// redirects the browser to GitLab's AuthURL
// (https://gitlab.com/oauth/authorize) with response_type=code. GitLab authorizes
// the user and redirects back to your callback route with a code, which the
// strategy exchanges for an access token at TokenURL
// (https://gitlab.com/oauth/token). It then GETs the UserInfoURL
// (https://gitlab.com/api/v4/user) with the bearer access token, builds an
// oauth2.Profile, and runs your verify func.
//
// This preset requests the read_user scope so the userinfo call can read the
// authenticated user's profile. The Profile.ID is derived best-effort from common
// raw keys (for GitLab this is typically "id" or "username"), with Provider set to
// "gitlab", Raw holding the decoded userinfo JSON, and AccessToken populated. Your
// oauth2.VerifyFunc returns (user, err): returning a nil user with a nil error
// rejects the authentication as a failure, while a non-nil error signals an
// internal error. CSRF protection via the state parameter is the caller's
// responsibility (passport threads ?state= through), and this base engine performs
// no PKCE. Note this preset targets GitLab.com; for a self-managed GitLab instance
// you would configure the generic oauth2 strategy with your own host.
//
// This package aims for behavioral parity with the Node passport-gitlab2 strategy
// while staying idiomatic Go and dependency-free. The preset endpoints and default
// scope mirror the upstream Passport.js module.
package gitlab

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Gitlab. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("gitlab", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://gitlab.com/oauth/authorize",
		TokenURL:     "https://gitlab.com/oauth/token",
		UserInfoURL:  "https://gitlab.com/api/v4/user",
		Scopes:       []string{"read_user"},
	}, verify)
}
