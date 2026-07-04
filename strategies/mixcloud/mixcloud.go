// Package mixcloud provides a passport OAuth2 strategy preset for Mixcloud.
package mixcloud

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Mixcloud.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("mixcloud", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.mixcloud.com/oauth/authorize",
		TokenURL:     "https://www.mixcloud.com/oauth/access_token",
	}, verify)
}
