// Package hubspot provides a passport OAuth2 strategy preset for HubSpot,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package hubspot

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for HubSpot. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("hubspot", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://app.hubspot.com/oauth/authorize",
		TokenURL:     "https://api.hubapi.com/oauth/v1/token",
		UserInfoURL:  "",
		Scopes:       []string{"oauth"},
	}, verify)
}
