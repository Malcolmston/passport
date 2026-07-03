// Package apple provides a passport OAuth2 strategy preset for the Apple
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package apple

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Apple. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("apple", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://appleid.apple.com/auth/authorize",
		TokenURL:     "https://appleid.apple.com/auth/token",
		UserInfoURL:  "",
		Scopes:       []string{"name", "email"},
	}, verify)
}
