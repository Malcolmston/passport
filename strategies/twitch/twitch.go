// Package twitch provides a passport OAuth2 strategy preset for the Twitch
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package twitch

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Twitch. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("twitch", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://id.twitch.tv/oauth2/authorize",
		TokenURL:     "https://id.twitch.tv/oauth2/token",
		UserInfoURL:  "https://api.twitch.tv/helix/users",
		Scopes:       []string{"user:read:email"},
	}, verify)
}
