// Package yandex provides a passport OAuth2 strategy preset for the Yandex
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package yandex

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Yandex. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("yandex", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://oauth.yandex.com/authorize",
		TokenURL:     "https://oauth.yandex.com/token",
		UserInfoURL:  "https://login.yandex.ru/info",
		Scopes:       []string{"login:email"},
	}, verify)
}
