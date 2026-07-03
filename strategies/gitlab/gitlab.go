// Package gitlab provides a passport OAuth2 strategy preset for the Gitlab
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package gitlab

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Gitlab. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("gitlab", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://gitlab.com/oauth/authorize",
		TokenURL:     "https://gitlab.com/oauth/token",
		UserInfoURL:  "https://gitlab.com/api/v4/user",
		Scopes:       []string{"read_user"},
	}, verify)
}
