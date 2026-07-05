// Package shopify provides a passport OAuth2 strategy preset for Shopify,
// porting the passport-shopify strategy from the Passport.js ecosystem. It is a
// thin configuration layer over strategies/oauth2: it fills in Shopify's
// per-shop authorization and token endpoints so callers only supply their app's
// API key and secret, a redirect URL and a verify function.
//
// Use this preset when you build a Shopify app that authorizes against a
// merchant's store. Shopify is per-shop: every store is served from its own
// {shop}.myshopify.com host, so the endpoints must be built from that domain.
// New uses a placeholder shop domain ("example.myshopify.com") so the
// zero-configuration call compiles and is discoverable; real deployments must
// call NewWithDomain with the merchant's actual myshopify.com domain (which your
// app typically learns from the ?shop parameter Shopify sends when the install
// begins).
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to {shop}.myshopify.com/admin/oauth/authorize, carrying
// the API key, redirect URI, requested scopes and an opaque state value. Shopify
// then redirects the browser back to the callback route with a ?code; the
// strategy exchanges that code at /admin/oauth/access_token for an access token.
// Mount one route for the redirect leg and one for the callback, both wired to
// the "shopify" strategy.
//
// The default scope is "read_products"; request the access scopes your app
// needs (for example "write_orders") by configuring them on the underlying
// oauth2 strategy. Shopify exposes no bearer userinfo endpoint on this flow, so
// no UserInfoURL is configured and the resulting profile is minimal; identify
// the shop from the domain or a follow-up Admin API call in your verify
// function. The state parameter should be a per-session random value used for
// CSRF protection; the surrounding passport session machinery round-trips it.
// Returning a nil user (with a nil error) rejects the login, while a non-nil
// error surfaces as an authentication error.
//
// Parity note: this preset covers the OAuth authorization-code grant used by
// public and custom apps. Verifying the HMAC signature that Shopify appends to
// the install/callback request, and honoring online vs offline access-token
// modes, are Shopify-specific concerns left to the caller, matching the scope of
// the Node original.
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
