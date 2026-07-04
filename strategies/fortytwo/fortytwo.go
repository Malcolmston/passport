// Package fortytwo provides a passport OAuth2 strategy preset for the 42 intra
// identity provider (api.intra.42.fr).
package fortytwo

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for 42 intra.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("fortytwo", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.intra.42.fr/oauth/authorize",
		TokenURL:     "https://api.intra.42.fr/oauth/token",
		UserInfoURL:  "https://api.intra.42.fr/v2/me",
		Scopes:       []string{"public"},
	}, verify)
}
