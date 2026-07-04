// Package deezer provides a passport OAuth2 strategy preset for Deezer.
package deezer

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Deezer.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("deezer", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.deezer.com/oauth/auth.php",
		TokenURL:     "https://connect.deezer.com/oauth/access_token.php",
		Scopes:       []string{"basic_access"},
	}, verify)
}
