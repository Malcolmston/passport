// Package auth0 provides a passport OAuth2 strategy preset for Auth0. Auth0 is
// domain-based: every tenant has its own host, so the endpoints are built
// from a domain. New uses a placeholder domain ("YOUR_DOMAIN.auth0.com"); use NewWithDomain to
// supply your real tenant domain.
package auth0

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder tenant host. Real deployments must supply
// their own domain via NewWithDomain.
const defaultDomain = "YOUR_DOMAIN.auth0.com"

// New returns an OAuth2 strategy for Auth0 using the placeholder domain
// ("YOUR_DOMAIN.auth0.com"). Prefer NewWithDomain to target your actual tenant.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Auth0 tenant domain
// (e.g. "your-tenant.auth0"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("auth0", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/authorize",
		TokenURL:     base + "/oauth/token",
		UserInfoURL:  base + "/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
