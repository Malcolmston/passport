// Package gumroad provides a passport OAuth2 strategy preset for Gumroad.
package gumroad

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Gumroad.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("gumroad", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://gumroad.com/oauth/authorize",
		TokenURL:     "https://gumroad.com/oauth/token",
		UserInfoURL:  "https://api.gumroad.com/v2/user",
	}, verify)
}
