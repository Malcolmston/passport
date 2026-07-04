// Package strava provides a passport OAuth2 strategy preset for Strava,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package strava

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Strava. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("strava", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.strava.com/oauth/authorize",
		TokenURL:     "https://www.strava.com/oauth/token",
		UserInfoURL:  "https://www.strava.com/api/v3/athlete",
		Scopes:       []string{"read"},
	}, verify)
}
