// Package instagram provides a passport OAuth2 strategy preset for Instagram,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package instagram

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Instagram. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("instagram", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.instagram.com/oauth/authorize",
		TokenURL:     "https://api.instagram.com/oauth/access_token",
		UserInfoURL:  "https://graph.instagram.com/me",
		Scopes:       []string{"user_profile"},
	}, verify)
}
