// Package box provides a passport OAuth2 strategy preset for Box,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package box

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Box. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("box", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://account.box.com/api/oauth2/authorize",
		TokenURL:     "https://api.box.com/oauth2/token",
		UserInfoURL:  "https://api.box.com/2.0/users/me",
		Scopes:       []string{},
	}, verify)
}
