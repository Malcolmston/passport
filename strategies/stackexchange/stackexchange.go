// Package stackexchange provides a passport OAuth2 strategy preset for the
// Stack Exchange network (authenticated via stackoverflow.com).
package stackexchange

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Stack Exchange.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("stackexchange", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://stackoverflow.com/oauth",
		TokenURL:     "https://stackoverflow.com/oauth/access_token",
	}, verify)
}
