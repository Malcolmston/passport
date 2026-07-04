// Package atlassian provides a passport OAuth2 strategy preset for Atlassian,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package atlassian

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Atlassian. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("atlassian", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://auth.atlassian.com/authorize",
		TokenURL:     "https://auth.atlassian.com/oauth/token",
		UserInfoURL:  "https://api.atlassian.com/me",
		Scopes:       []string{"read:me"},
	}, verify)
}
