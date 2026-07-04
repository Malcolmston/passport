// Package vk provides a passport OAuth2 strategy preset for VK,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package vk

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for VK. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("vk", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://oauth.vk.com/authorize",
		TokenURL:     "https://oauth.vk.com/access_token",
		UserInfoURL:  "https://api.vk.com/method/users.get",
		Scopes:       []string{"email"},
	}, verify)
}
