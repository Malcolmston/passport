// Package imgur provides a passport OAuth2 strategy preset for Imgur.
package imgur

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Imgur.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("imgur", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.imgur.com/oauth2/authorize",
		TokenURL:     "https://api.imgur.com/oauth2/token",
		UserInfoURL:  "https://api.imgur.com/3/account/me",
	}, verify)
}
