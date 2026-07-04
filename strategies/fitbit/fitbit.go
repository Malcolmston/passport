// Package fitbit provides a passport OAuth2 strategy preset for Fitbit,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package fitbit

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Fitbit. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("fitbit", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.fitbit.com/oauth2/authorize",
		TokenURL:     "https://api.fitbit.com/oauth2/token",
		UserInfoURL:  "https://api.fitbit.com/1/user/-/profile.json",
		Scopes:       []string{"profile"},
	}, verify)
}
