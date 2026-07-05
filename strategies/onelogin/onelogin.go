// Package onelogin provides a passport OAuth2/OIDC strategy preset for
// OneLogin, porting the passport-onelogin / passport-oauth2 wiring used against
// OneLogin's OpenID Connect endpoints. It is a thin configuration layer over
// strategies/oauth2: it fills in OneLogin's authorization, token and userinfo
// endpoints so callers only supply their client credentials, a redirect URL and
// a verify function.
//
// Use this preset when your users authenticate against a OneLogin account using
// the standard OAuth 2.0 authorization-code flow. OneLogin is subdomain-based:
// each account lives at {subdomain}.onelogin.com, so the endpoints must be built
// from that host. New uses a placeholder domain ("example.onelogin.com") so the
// zero-configuration call compiles and is discoverable; real deployments must
// call NewWithDomain with their actual account host.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to OneLogin's /oidc/2/auth endpoint, carrying the client
// ID, redirect URI, requested scopes and an opaque state value. After the user
// authenticates, OneLogin redirects the browser back to the callback route with
// a ?code; the strategy exchanges that code at /oidc/2/token for an access token
// and calls /oidc/2/me to fetch the profile. Mount one route for the redirect
// leg and one for the callback, both wired to the "onelogin" strategy.
//
// The default scopes are "openid", "email" and "profile". The state parameter
// should be a per-session random value used for CSRF protection; the surrounding
// passport session machinery round-trips it. The verify function receives the
// fetched oauth2.Profile and maps it to your application user; returning a nil
// user (with a nil error) rejects the login, while a non-nil error surfaces as
// an authentication error.
//
// Parity note: like the Node original this preset only presets endpoints and
// default scopes; it does not itself validate the OIDC id_token that OneLogin
// returns when "openid" is requested. For strict id_token signature and issuer
// validation via OneLogin's JWKS, use strategies/openidconnect configured with
// OneLogin's discovery endpoints instead.
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
