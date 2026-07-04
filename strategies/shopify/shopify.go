// Package shopify provides a passport OAuth2 strategy preset for Shopify.
// Shopify is per-shop: every store has its own {shop}.myshopify.com host, so the
// endpoints are built from that domain. New uses a placeholder shop domain; use
// NewWithDomain to supply your store's real myshopify.com domain.
package shopify

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is a placeholder shop host. Real deployments must supply their
// own store domain via NewWithDomain.
const defaultDomain = "example.myshopify.com"

// New returns an OAuth2 strategy for Shopify using the placeholder shop domain
// ("example.myshopify.com"). Prefer NewWithDomain to target your actual store.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Shopify store domain
// (e.g. "your-store.myshopify.com"), without scheme. Shopify exposes no bearer
// userinfo endpoint on this flow, so no UserInfoURL is configured.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("shopify", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/admin/oauth/authorize",
		TokenURL:     base + "/admin/oauth/access_token",
		Scopes:       []string{"read_products"},
	}, verify)
}
