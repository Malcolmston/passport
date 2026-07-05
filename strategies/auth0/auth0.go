// Package auth0 provides an OAuth2/OIDC "Sign in with Auth0" authentication
// strategy for the passport port. It is the Go equivalent of the passport-auth0
// strategy for Passport.js and authenticates users against an Auth0 tenant's
// hosted login. The package is a preset over the shared strategies/oauth2
// engine: because every Auth0 tenant is served from its own host, the
// authorization (/authorize), token (/oauth/token) and userinfo (/userinfo)
// endpoints are derived from a tenant domain rather than hard-coded.
//
// Use this strategy when your identity provider is Auth0 and you want to
// delegate login (including Auth0's social connections, database users and
// enterprise SSO) to the Auth0 Universal Login page. New targets a placeholder
// domain ("YOUR_DOMAIN.auth0.com") and exists mainly so the package satisfies
// the common New(...) shape; real deployments must call NewWithDomain to point
// the strategy at their actual tenant domain (for example
// "your-tenant.us.auth0.com").
//
// The flow is the standard OAuth2 authorization-code grant with OIDC scopes. On
// the initiation route there is no ?code=, so Authenticate redirects the browser
// to the tenant's /authorize page with the client ID, redirect URI, scopes and
// optional state. Auth0 authenticates the user and redirects back to the
// callback route with a ?code=; the strategy exchanges the code at /oauth/token,
// fetches the profile from /userinfo, and runs the verify function.
//
// The default scopes are "openid", "email" and "profile", so the OIDC userinfo
// response includes the stable subject ("sub"), email and display name. The
// oauth2.Profile handed to verify carries the provider name ("auth0"), the
// provider ID, the decoded userinfo in Raw, and the AccessToken. As with any
// redirect strategy the caller should pass and validate a state value for CSRF
// protection. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-auth0 this performs the authorization-code exchange and
// reads the OIDC userinfo profile, but the Go port normalizes the result into an
// oauth2.Profile, does not (yet) validate or decode the id_token itself, and
// leaves session establishment and route wiring to the surrounding
// passport.Passport instance. Refresh tokens, audience/organization parameters
// and Auth0 logout are out of scope for this preset.
package auth0

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder tenant host. Real deployments must supply
// their own domain via NewWithDomain.
const defaultDomain = "YOUR_DOMAIN.auth0.com"

// New returns an OAuth2 strategy for Auth0 using the placeholder domain
// ("YOUR_DOMAIN.auth0.com"). Prefer NewWithDomain to target your actual tenant.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Auth0 tenant domain
// (e.g. "your-tenant.auth0"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("auth0", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/authorize",
		TokenURL:     base + "/oauth/token",
		UserInfoURL:  base + "/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
