// Package notion provides a passport OAuth2 strategy preset for Notion,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package notion

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Notion. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("notion", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.notion.com/v1/oauth/authorize",
		TokenURL:     "https://api.notion.com/v1/oauth/token",
		UserInfoURL:  "https://api.notion.com/v1/users/me",
		Scopes:       []string{},
	}, verify)
}
