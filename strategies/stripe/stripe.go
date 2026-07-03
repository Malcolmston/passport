// Package stripe provides a passport OAuth2 strategy preset for the Stripe
// identity provider, wrapping strategies/oauth2 with the provider's public
// authorization, token and userinfo endpoints.
package stripe

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Stripe. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("stripe", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://connect.stripe.com/oauth/authorize",
		TokenURL:     "https://connect.stripe.com/oauth/token",
		UserInfoURL:  "",
		Scopes:       []string{"read_only"},
	}, verify)
}
