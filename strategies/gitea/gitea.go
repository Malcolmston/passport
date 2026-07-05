// Package gitea provides a passport OAuth2 authorization-code strategy preset for
// the Gitea identity provider. It is a thin wrapper around the shared
// strategies/oauth2 engine, pre-configured with Gitea's authorization, token and
// userinfo endpoint paths, and it ports the community Node passport-gitea strategy
// to Go using only the standard library.
//
// Use this package when you want users to sign in to your application with an
// account on a Gitea server. Because Gitea is self-hosted, its endpoints are
// derived from the instance host: NewWithDomain builds the AuthURL, TokenURL and
// UserInfoURL from a host such as "gitea.example.com". Call NewWithDomain (or New)
// with your OAuth2 application credentials and redirect URL, supply an
// oauth2.VerifyFunc, and register the resulting *oauth2.Strategy with passport via
// Passport.Use. New exists mainly for symmetry with the other presets: it uses the
// placeholder host "gitea.example.com" (the defaultHost constant), which is almost
// never what you want, so prefer NewWithDomain to point at your real instance.
//
// The strategy drives the standard OAuth2 authorization-code flow. When
// Strategy.Authenticate handles a request without a ?code= query parameter, it
// redirects the browser to the instance AuthURL
// (https://<host>/login/oauth/authorize) with response_type=code. Gitea authorizes
// the user and redirects back to your callback route with a code, which the
// strategy exchanges for an access token at TokenURL
// (https://<host>/login/oauth/access_token). It then GETs the UserInfoURL
// (https://<host>/api/v1/user) with the bearer access token, builds an
// oauth2.Profile, and runs your verify func.
//
// This preset configures no default scopes; Gitea returns the authenticated user
// from its /api/v1/user endpoint using the granted token. The Profile.ID is derived
// best-effort from common raw keys (for Gitea this is typically "id" or "login"),
// with Provider set to "gitea", Raw holding the decoded userinfo JSON, and
// AccessToken populated. Your oauth2.VerifyFunc returns (user, err): returning a nil
// user with a nil error rejects the authentication as a failure, while a non-nil
// error signals an internal error. CSRF protection via the state parameter is the
// caller's responsibility (passport threads ?state= through), and this base engine
// performs no PKCE.
//
// This package aims for behavioral parity with the community Node passport-gitea
// strategy while staying idiomatic Go and dependency-free. The per-host endpoint
// construction mirrors the upstream Passport.js module's handling of self-hosted
// Gitea instances.
package gitea

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultHost is a placeholder Gitea host.
const defaultHost = "gitea.example.com"

// New returns an OAuth2 strategy for Gitea using the placeholder host. Prefer
// NewWithDomain to target your actual instance.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultHost, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Gitea host
// (e.g. "gitea.example.com"), without scheme.
func NewWithDomain(host, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + host
	return oauth2.New("gitea", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/login/oauth/authorize",
		TokenURL:     base + "/login/oauth/access_token",
		UserInfoURL:  base + "/api/v1/user",
	}, verify)
}
