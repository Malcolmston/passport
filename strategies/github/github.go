// Package github provides a passport OAuth2 strategy preset for the Github
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package github

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Github. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("github", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"read:user", "user:email"},
	}, verify)
}
