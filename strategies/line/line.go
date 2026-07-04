// Package line provides a passport OAuth2 strategy preset for LINE,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package line

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for LINE. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("line", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:     "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:  "https://api.line.me/v2/profile",
		Scopes:       []string{"profile", "openid", "email"},
	}, verify)
}
