// Package discord provides a passport OAuth2 strategy preset for the Discord
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package discord

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Discord. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("discord", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://discord.com/api/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserInfoURL:  "https://discord.com/api/users/@me",
		Scopes:       []string{"identify", "email"},
	}, verify)
}
