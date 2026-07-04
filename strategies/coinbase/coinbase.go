// Package coinbase provides a passport OAuth2 strategy preset for Coinbase.
package coinbase

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Coinbase.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("coinbase", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://login.coinbase.com/oauth2/auth",
		TokenURL:     "https://api.coinbase.com/oauth/token",
		UserInfoURL:  "https://api.coinbase.com/v2/user",
		Scopes:       []string{"wallet:user:read"},
	}, verify)
}
