// Package pinterest provides a passport OAuth2 strategy preset for Pinterest,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package pinterest

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Pinterest. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("pinterest", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.pinterest.com/oauth/",
		TokenURL:     "https://api.pinterest.com/v5/oauth/token",
		UserInfoURL:  "https://api.pinterest.com/v5/user_account",
		Scopes:       []string{"user_accounts:read"},
	}, verify)
}
