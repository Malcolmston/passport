// Package naver provides a passport OAuth2 strategy preset for Naver,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package naver

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Naver. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("naver", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://nid.naver.com/oauth2.0/authorize",
		TokenURL:     "https://nid.naver.com/oauth2.0/token",
		UserInfoURL:  "https://openapi.naver.com/v1/nid/me",
		Scopes:       []string{},
	}, verify)
}
