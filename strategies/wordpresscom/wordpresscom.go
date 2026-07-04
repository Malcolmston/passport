// Package wordpresscom provides a passport OAuth2 strategy preset for
// WordPress.com (public-api.wordpress.com).
package wordpresscom

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for WordPress.com.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("wordpresscom", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://public-api.wordpress.com/oauth2/authorize",
		TokenURL:     "https://public-api.wordpress.com/oauth2/token",
		UserInfoURL:  "https://public-api.wordpress.com/rest/v1/me",
	}, verify)
}
