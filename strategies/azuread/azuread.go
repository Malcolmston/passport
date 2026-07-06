// Package azuread provides an OAuth2/OIDC "Sign in with Microsoft" authentication
// strategy for the passport port, targeting Azure AD (the Microsoft identity
// platform v2.0). It is the Go analogue of the passport-azure-ad family of
// strategies for Passport.js. The package is a preset over the shared
// strategies/oauth2 engine: the authorization and token endpoints are built
// under https://login.microsoftonline.com/<tenant>/oauth2/v2.0, and the profile
// is read from the Microsoft Graph OIDC userinfo endpoint
// (https://graph.microsoft.com/oidc/userinfo).
//
// Use this strategy to let users sign in with a Microsoft work, school or
// personal account. New targets the multi-tenant "common" endpoint, which
// accepts any Azure AD or personal Microsoft account; call NewWithTenant to
// restrict login to a specific tenant (a tenant id or domain) or to the
// "organizations" or "consumers" audiences.
//
// The flow is the standard OAuth2 authorization-code grant with OIDC scopes. On
// the initiation route there is no ?code=, so Authenticate redirects the browser
// to the v2.0 /authorize endpoint with the client ID, redirect URI, scopes and
// optional state. Azure AD authenticates the user and redirects back to the
// callback route with a ?code=; the strategy exchanges the code at the /token
// endpoint, GETs the Graph userinfo endpoint, and runs the verify function.
//
// The default scopes are "openid", "email" and "profile", so the userinfo
// response includes the subject ("sub"), email and display name. The
// oauth2.Profile handed to verify carries the provider name ("azuread"), the
// provider ID, the decoded userinfo in Raw, and the AccessToken. As with any
// redirect strategy the caller should pass and validate a state value for CSRF
// protection. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like the Node passport-azure-ad strategies this performs the v2.0
// authorization-code exchange and reads an OIDC profile, but the Go port keeps
// the mechanism deliberately small: it normalizes the profile into an
// oauth2.Profile, does not validate the id_token signature or nonce, and leaves
// session handling, PKCE, on-behalf-of tokens and admin-consent flows to the
// caller and the surrounding passport.Passport instance.
package azuread

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy for Azure AD using the "common" endpoint.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithTenant("common", clientID, clientSecret, redirectURL, verify)
}

// NewWithTenant returns an OAuth2 strategy for the given Azure AD tenant (a
// tenant ID/domain, or "common", "organizations", "consumers").
func NewWithTenant(tenant, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0"
	return oauth2.New("azuread", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/authorize",
		TokenURL:     base + "/token",
		UserInfoURL:  "https://graph.microsoft.com/oidc/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
