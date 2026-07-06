// Package keycloak provides a passport OAuth2/OIDC strategy preset for Keycloak,
// the open-source identity and access management server. It is a thin wrapper
// over strategies/oauth2 and ports passport-keycloak-oauth2-oidc: New and
// NewWithRealm return a *oauth2.Strategy, so the full OAuth2 base API and its
// documented semantics apply here unchanged.
//
// Use this package to authenticate against your own Keycloak deployment. Because
// Keycloak is self-hosted and realm-scoped, its OpenID Connect endpoints are
// derived from the server host and realm name rather than being fixed. Prefer
// NewWithRealm, which builds the endpoints from the host (for example
// "keycloak.example.com", without a scheme) and realm you supply; New exists for
// convenience and uses placeholder host and realm values that you will almost
// always want to override.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package. A login request with no "code" redirects the browser to the realm's
// authorization endpoint (/realms/<realm>/protocol/openid-connect/auth); after
// the user signs in, Keycloak redirects back to your callback with a code that
// is exchanged at the token endpoint and used to fetch claims from the userinfo
// endpoint. All three endpoints live under the same realm base URL.
//
// The default scopes are "openid", "email", and "profile" — "openid" makes this
// an OpenID Connect request, so the userinfo endpoint returns standard claims
// (the subject arrives as "sub", which the base package uses for Profile.ID).
// As with every OAuth2 strategy here, "state" is passed through for CSRF
// protection but owned by the surrounding passport middleware, and PKCE is not
// used. Make sure the redirect URL you pass exactly matches a valid redirect URI
// configured on the Keycloak client.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-keycloak-oauth2-oidc, this port does not validate the ID token
// signature itself; it relies on the userinfo response fetched over TLS and
// leaves any additional token handling to your verify function.
package keycloak

import "github.com/malcolmston/passport/strategies/oauth2"

const (
	defaultHost  = "keycloak.example.com"
	defaultRealm = "master"
)

// New returns an OAuth2 strategy for Keycloak using placeholder host and realm.
// Prefer NewWithRealm to target your actual server and realm.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithRealm(defaultHost, defaultRealm, clientID, clientSecret, redirectURL, verify)
}

// NewWithRealm returns an OAuth2 strategy for the given Keycloak host
// (e.g. "keycloak.example.com", without scheme) and realm.
func NewWithRealm(host, realm, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + host + "/realms/" + realm + "/protocol/openid-connect"
	return oauth2.New("keycloak", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/auth",
		TokenURL:     base + "/token",
		UserInfoURL:  base + "/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
