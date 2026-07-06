// Package microsoft provides a passport OAuth2/OIDC strategy preset for the
// Microsoft identity platform (Azure AD / Entra ID), which backs "Sign in with
// Microsoft" for both work/school and personal accounts. It is a thin wrapper
// over strategies/oauth2 that presets the v2.0 authorization, token, and Graph
// profile endpoints, and it ports passport-microsoft. New returns a
// *oauth2.Strategy, so the full OAuth2 base API and its documented semantics
// apply here unchanged.
//
// Use this package to let users log in with a Microsoft account. Register an
// application in the Azure portal (Entra ID app registrations), then call New
// with the application (client) ID, a client secret, and the redirect URI you
// registered, plus a verify function that maps the returned profile to your
// application user.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to the v2.0
// authorize endpoint, and Microsoft redirects back to your callback with a code
// that is exchanged at the v2.0 token endpoint and used to fetch the user's
// profile from Microsoft Graph (https://graph.microsoft.com/v1.0/me).
//
// This preset targets the "common" tenant, so it accepts both organizational and
// personal Microsoft accounts; register a single-tenant app and build endpoints
// yourself if you need to restrict that. The default scopes are "openid",
// "email", and "profile", making this an OpenID Connect request. Graph returns
// the object id under "id", which the base package uses for Profile.ID. As with
// every OAuth2 strategy here, "state" is passed through for CSRF protection but
// owned by the surrounding passport middleware, and PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-microsoft, this port exposes the raw Graph response on Profile.Raw
// and leaves profile normalization and any ID-token handling to your verify
// function.
package microsoft

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Microsoft. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("microsoft", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
