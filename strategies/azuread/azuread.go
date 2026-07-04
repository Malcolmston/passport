// Package azuread provides a passport OAuth2 strategy preset for Azure AD
// (Microsoft identity platform v2.0). New targets the multi-tenant "common"
// endpoint; use NewWithTenant to target a specific tenant.
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
