// Package onelogin provides a passport OAuth2 strategy preset for OneLogin
// (OIDC). OneLogin is subdomain-based: each account lives at
// {sub}.onelogin.com. New uses a placeholder domain; use NewWithDomain to
// supply your real host.
package onelogin

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder OneLogin host.
const defaultDomain = "example.onelogin.com"

// New returns an OAuth2 strategy for OneLogin using the placeholder domain.
// Prefer NewWithDomain to target your actual account.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given OneLogin host
// (e.g. "your-account.onelogin.com"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("onelogin", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oidc/2/auth",
		TokenURL:     base + "/oidc/2/token",
		UserInfoURL:  base + "/oidc/2/me",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
