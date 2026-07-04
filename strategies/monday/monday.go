// Package monday provides a passport OAuth2 strategy preset for monday.com.
package monday

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for monday.com.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("monday", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.monday.com/oauth2/authorize",
		TokenURL:     "https://auth.monday.com/oauth2/token",
	}, verify)
}
