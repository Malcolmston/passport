// Package eventbrite provides a passport OAuth2 strategy preset for Eventbrite.
package eventbrite

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Eventbrite.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("eventbrite", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.eventbrite.com/oauth/authorize",
		TokenURL:     "https://www.eventbrite.com/oauth/token",
		UserInfoURL:  "https://www.eventbriteapi.com/v3/users/me",
	}, verify)
}
