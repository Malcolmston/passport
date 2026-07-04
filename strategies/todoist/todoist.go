// Package todoist provides a passport OAuth2 strategy preset for Todoist.
package todoist

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Todoist.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("todoist", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://todoist.com/oauth/authorize",
		TokenURL:     "https://todoist.com/oauth/access_token",
		Scopes:       []string{"data:read"},
	}, verify)
}
