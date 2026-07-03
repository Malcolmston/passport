// Package okta provides a passport OAuth2 strategy preset for Okta. Okta is
// domain-based: every tenant has its own host, so the endpoints are built
// from a domain. New uses a placeholder domain ("example.okta.com"); use NewWithDomain to
// supply your real tenant domain.
package okta

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder tenant host. Real deployments must supply
// their own domain via NewWithDomain.
const defaultDomain = "example.okta.com"

// New returns an OAuth2 strategy for Okta using the placeholder domain
// ("example.okta.com"). Prefer NewWithDomain to target your actual tenant.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Okta tenant domain
// (e.g. "your-tenant.okta.com"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("okta", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oauth2/v1/authorize",
		TokenURL:     base + "/oauth2/v1/token",
		UserInfoURL:  base + "/oauth2/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
