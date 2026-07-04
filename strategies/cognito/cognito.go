// Package cognito provides a passport OAuth2 strategy preset for Amazon Cognito
// hosted UI. Cognito is domain-based: each user pool has its own domain. New
// uses a placeholder domain; use NewWithDomain to supply your real domain.
package cognito

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder Cognito hosted-UI domain.
const defaultDomain = "example.auth.us-east-1.amazoncognito.com"

// New returns an OAuth2 strategy for Cognito using the placeholder domain.
// Prefer NewWithDomain to target your actual user pool domain.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Cognito hosted-UI
// domain (e.g. "your-pool.auth.us-east-1.amazoncognito.com"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("cognito", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oauth2/authorize",
		TokenURL:     base + "/oauth2/token",
		UserInfoURL:  base + "/oauth2/userInfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
