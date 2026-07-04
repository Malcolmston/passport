// Package digitalocean provides a passport OAuth2 strategy preset for DigitalOcean,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package digitalocean

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for DigitalOcean. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("digitalocean", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://cloud.digitalocean.com/v1/oauth/authorize",
		TokenURL:     "https://cloud.digitalocean.com/v1/oauth/token",
		UserInfoURL:  "https://api.digitalocean.com/v2/account",
		Scopes:       []string{"read"},
	}, verify)
}
