// Package workos provides a passport OAuth2 strategy preset for WorkOS SSO.
package workos

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for WorkOS SSO.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("workos", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://api.workos.com/sso/authorize",
		TokenURL:     "https://api.workos.com/sso/token",
	}, verify)
}
