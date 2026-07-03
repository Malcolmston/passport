// Package slack provides a passport OAuth2 strategy preset for the Slack
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package slack

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Slack. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("slack", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://slack.com/openid/connect/authorize",
		TokenURL:     "https://slack.com/api/openid.connect.token",
		UserInfoURL:  "https://slack.com/api/openid.connect.userInfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
