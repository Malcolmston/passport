// Package linkedin provides a passport OAuth2 strategy preset for the Linkedin
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package linkedin

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Linkedin. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("linkedin", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:  "https://api.linkedin.com/v2/me",
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
	}, verify)
}
