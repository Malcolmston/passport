// Package okta provides a passport OAuth2/OIDC strategy preset for Okta,
// porting the passport-okta-oauth wiring used against Okta in the Passport.js
// ecosystem. It is a thin configuration layer over strategies/oauth2: it fills
// in Okta's authorization, token and userinfo endpoints so callers only supply
// their client credentials, a redirect URL and a verify function.
//
// Use this preset when you want users to sign in with an Okta org (workforce or
// customer identity) using the standard OAuth 2.0 authorization-code flow. Okta
// is domain-based: every tenant is served from its own host
// (your-tenant.okta.com, or a custom domain), so the endpoints must be built
// from that host. New uses a placeholder domain ("example.okta.com") purely so
// the zero-configuration call compiles and is discoverable; real deployments
// must call NewWithDomain with their actual tenant domain.
//
// The flow has two legs. On the first request the strategy finds no ?code in
// the query and issues a 302 redirect to Okta's /oauth2/v1/authorize endpoint,
// carrying the client ID, redirect URI, requested scopes and an opaque state
// value. After the user authenticates and consents, Okta redirects the browser
// back to the callback route with a ?code; the strategy then exchanges that code
// at /oauth2/v1/token for an access token and calls /oauth2/v1/userinfo to fetch
// the profile. Mount one route for the redirect leg and one for the callback,
// both wired to the "okta" strategy.
//
// The default scopes are "openid", "email" and "profile", which yield the
// user's subject, email and basic profile from the userinfo endpoint. The state
// parameter should be a per-session random value used for CSRF protection; the
// surrounding passport session machinery round-trips it. The verify function
// receives the fetched oauth2.Profile and maps it to your application user;
// returning a nil user (with a nil error) rejects the login, while a non-nil
// error surfaces as an authentication error. Profile.ID is derived from the
// provider's userinfo response.
//
// Parity note: like the Node original this preset only presets endpoints and
// default scopes; it does not itself validate the OIDC id_token. Okta returns
// one when "openid" is requested, but this OAuth2 wrapper treats the login as an
// access-token exchange plus userinfo call. For strict id_token signature and
// issuer validation via Okta's JWKS, use strategies/openidconnect configured
// with Okta's discovery endpoints instead.
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
