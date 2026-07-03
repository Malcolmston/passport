// Package amazon provides a passport OAuth2 strategy preset for the Amazon
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package amazon

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Amazon. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("amazon", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.amazon.com/ap/oa",
		TokenURL:     "https://api.amazon.com/auth/o2/token",
		UserInfoURL:  "https://api.amazon.com/user/profile",
		Scopes:       []string{"profile"},
	}, verify)
}
