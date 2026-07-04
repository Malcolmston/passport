// Package etsy provides a passport OAuth2 strategy preset for Etsy (Open API v3).
package etsy

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Etsy.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("etsy", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.etsy.com/oauth/connect",
		TokenURL:     "https://api.etsy.com/v3/public/oauth/token",
	}, verify)
}
