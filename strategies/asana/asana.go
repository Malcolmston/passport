// Package asana provides a passport OAuth2 strategy preset for Asana,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package asana

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Asana. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("asana", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.asana.com/-/oauth_authorize",
		TokenURL:     "https://app.asana.com/-/oauth_token",
		UserInfoURL:  "https://app.asana.com/api/1.0/users/me",
		Scopes:       []string{},
	}, verify)
}
