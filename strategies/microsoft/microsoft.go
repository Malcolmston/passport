// Package microsoft provides a passport OAuth2 strategy preset for the Microsoft
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
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
