// Package square provides a passport OAuth2 strategy preset for Square,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package square

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Square. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("square", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.squareup.com/oauth2/authorize",
		TokenURL:     "https://connect.squareup.com/oauth2/token",
		UserInfoURL:  "",
		Scopes:       []string{"MERCHANT_PROFILE_READ"},
	}, verify)
}
