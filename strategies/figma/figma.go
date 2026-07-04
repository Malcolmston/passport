// Package figma provides a passport OAuth2 strategy preset for Figma,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package figma

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Figma. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("figma", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.figma.com/oauth",
		TokenURL:     "https://api.figma.com/v1/oauth/token",
		UserInfoURL:  "https://api.figma.com/v1/me",
		Scopes:       []string{"files:read"},
	}, verify)
}
