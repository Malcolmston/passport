// Package kakao provides a passport OAuth2 strategy preset for Kakao,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package kakao

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Kakao. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("kakao", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://kauth.kakao.com/oauth/authorize",
		TokenURL:     "https://kauth.kakao.com/oauth/token",
		UserInfoURL:  "https://kapi.kakao.com/v2/user/me",
		Scopes:       []string{"profile_nickname", "account_email"},
	}, verify)
}
