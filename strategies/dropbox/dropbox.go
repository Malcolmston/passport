// Package dropbox provides a passport OAuth2 strategy preset for the Dropbox
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package dropbox

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Dropbox. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("dropbox", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.dropbox.com/oauth2/authorize",
		TokenURL:     "https://api.dropboxapi.com/oauth2/token",
		UserInfoURL:  "https://api.dropboxapi.com/2/users/get_current_account",
		Scopes:       nil,
	}, verify)
}
