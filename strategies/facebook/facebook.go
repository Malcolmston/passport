// Package facebook provides a passport OAuth2 strategy preset for the Facebook
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package facebook

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Facebook. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("facebook", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.facebook.com/v12.0/dialog/oauth",
		TokenURL:     "https://graph.facebook.com/v12.0/oauth/access_token",
		UserInfoURL:  "https://graph.facebook.com/me?fields=id,name,email",
		Scopes:       []string{"email"},
	}, verify)
}
