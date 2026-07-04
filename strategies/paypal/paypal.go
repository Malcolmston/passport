// Package paypal provides a passport OAuth2 strategy preset for PayPal,
// wrapping strategies/oauth2 with the provider's authorization, token and
// userinfo endpoints.
package paypal

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for PayPal. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("paypal", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.paypal.com/signin/authorize",
		TokenURL:     "https://api-m.paypal.com/v1/oauth2/token",
		UserInfoURL:  "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
