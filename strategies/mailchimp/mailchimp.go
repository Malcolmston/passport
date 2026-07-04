// Package mailchimp provides a passport OAuth2 strategy preset for Mailchimp,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package mailchimp

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Mailchimp. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("mailchimp", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://login.mailchimp.com/oauth2/authorize",
		TokenURL:     "https://login.mailchimp.com/oauth2/token",
		UserInfoURL:  "https://login.mailchimp.com/oauth2/metadata",
		Scopes:       []string{},
	}, verify)
}
