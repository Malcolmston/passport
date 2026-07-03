// Package twitter provides a passport OAuth2 strategy preset for the Twitter
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package twitter

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Twitter. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("twitter", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://twitter.com/i/oauth2/authorize",
		TokenURL:     "https://api.twitter.com/2/oauth2/token",
		UserInfoURL:  "https://api.twitter.com/2/users/me",
		Scopes:       []string{"tweet.read", "users.read"},
	}, verify)
}
