// Package patreon provides a passport OAuth2 strategy preset for Patreon,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package patreon

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Patreon. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("patreon", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.patreon.com/oauth2/authorize",
		TokenURL:     "https://api.patreon.com/oauth2/token",
		UserInfoURL:  "https://api.patreon.com/oauth2/v2/identity",
		Scopes:       []string{"identity"},
	}, verify)
}
