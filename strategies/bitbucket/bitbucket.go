// Package bitbucket provides a passport OAuth2 strategy preset for the Bitbucket
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package bitbucket

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Bitbucket. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("bitbucket", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://bitbucket.org/site/oauth2/authorize",
		TokenURL:     "https://bitbucket.org/site/oauth2/access_token",
		UserInfoURL:  "https://api.bitbucket.org/2.0/user",
		Scopes:       []string{"account"},
	}, verify)
}
