// Package heroku provides a passport OAuth2 strategy preset for Heroku,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package heroku

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Heroku. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("heroku", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://id.heroku.com/oauth/authorize",
		TokenURL:     "https://id.heroku.com/oauth/token",
		UserInfoURL:  "https://api.heroku.com/account",
		Scopes:       []string{"identity"},
	}, verify)
}
