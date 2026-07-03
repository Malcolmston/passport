// Package reddit provides a passport OAuth2 strategy preset for the Reddit
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package reddit

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Reddit. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("reddit", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.reddit.com/api/v1/authorize",
		TokenURL:     "https://www.reddit.com/api/v1/access_token",
		UserInfoURL:  "https://oauth.reddit.com/api/v1/me",
		Scopes:       []string{"identity"},
	}, verify)
}
