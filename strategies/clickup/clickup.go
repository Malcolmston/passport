// Package clickup provides a passport OAuth2 strategy preset for ClickUp.
package clickup

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for ClickUp.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("clickup", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.clickup.com/api",
		TokenURL:     "https://api.clickup.com/api/v2/oauth/token",
		UserInfoURL:  "https://api.clickup.com/api/v2/user",
	}, verify)
}
