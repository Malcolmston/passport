// Package meetup provides a passport OAuth2 strategy preset for Meetup.
package meetup

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Meetup.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("meetup", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://secure.meetup.com/oauth2/authorize",
		TokenURL:     "https://secure.meetup.com/oauth2/access",
	}, verify)
}
