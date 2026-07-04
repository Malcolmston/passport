// Package zendesk provides a passport OAuth2 strategy preset for Zendesk.
// Zendesk is subdomain-based: each account lives at {sub}.zendesk.com. New
// uses a placeholder domain; use NewWithDomain to supply your real host.
package zendesk

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder Zendesk host.
const defaultDomain = "example.zendesk.com"

// New returns an OAuth2 strategy for Zendesk using the placeholder domain.
// Prefer NewWithDomain to target your actual account.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Zendesk host
// (e.g. "your-account.zendesk.com"), without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("zendesk", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oauth/authorizations/new",
		TokenURL:     base + "/oauth/tokens",
		Scopes:       []string{"read"},
	}, verify)
}
