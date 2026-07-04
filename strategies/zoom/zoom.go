// Package zoom provides a passport OAuth2 strategy preset for Zoom,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package zoom

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Zoom. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("zoom", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://zoom.us/oauth/authorize",
		TokenURL:     "https://zoom.us/oauth/token",
		UserInfoURL:  "https://api.zoom.us/v2/users/me",
		Scopes:       []string{"user:read"},
	}, verify)
}
