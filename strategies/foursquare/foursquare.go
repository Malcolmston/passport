// Package foursquare provides a passport OAuth2 strategy preset for Foursquare.
package foursquare

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Foursquare.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("foursquare", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://foursquare.com/oauth2/authenticate",
		TokenURL:     "https://foursquare.com/oauth2/access_token",
	}, verify)
}
