// Package spotify provides a passport OAuth2 strategy preset for the Spotify
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package spotify

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Spotify. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("spotify", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://accounts.spotify.com/authorize",
		TokenURL:     "https://accounts.spotify.com/api/token",
		UserInfoURL:  "https://api.spotify.com/v1/me",
		Scopes:       []string{"user-read-email"},
	}, verify)
}
