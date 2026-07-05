// Package salesforce provides a passport OAuth2/OIDC strategy preset for
// Salesforce, porting the passport-salesforce (Force.com / OpenID Connect)
// wiring from the Passport.js ecosystem. It is a thin configuration layer over
// strategies/oauth2: it fills in Salesforce's authorization, token and userinfo
// endpoints so callers only supply their connected-app credentials, a redirect
// URL and a verify function.
//
// Use this preset when you want users to sign in with their Salesforce org.
// Salesforce authenticates against a login host: login.salesforce.com for
// production orgs, test.salesforce.com for sandboxes, and a My Domain host
// (your-domain.my.salesforce.com) for orgs with My Domain enabled. New targets
// the production login host; call NewWithDomain to point at a sandbox or My
// Domain host.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to /services/oauth2/authorize on the login host,
// carrying the client ID, redirect URI, requested scopes and an opaque state
// value. Salesforce then redirects the browser back to the callback route with a
// ?code; the strategy exchanges that code at /services/oauth2/token for an
// access token and calls /services/oauth2/userinfo to fetch the profile. Mount
// one route for the redirect leg and one for the callback, both wired to the
// "salesforce" strategy.
//
// The default scopes are "openid", "email" and "profile". Note that the
// connected app in Salesforce must have the corresponding OAuth scopes enabled,
// and the token response also carries an instance URL that identifies the org's
// API host for subsequent calls. The state parameter should be a per-session
// random value used for CSRF protection; the surrounding passport session
// machinery round-trips it. The verify function receives the fetched
// oauth2.Profile and maps it to your application user; returning a nil user
// (with a nil error) rejects the login, while a non-nil error surfaces as an
// authentication error.
//
// Parity note: like the Node original this preset presets endpoints and default
// scopes only; it does not itself validate the OIDC id_token that Salesforce
// returns when "openid" is requested. For strict id_token signature and issuer
// validation, use strategies/openidconnect configured with Salesforce's
// discovery endpoints.
package salesforce

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is the production Salesforce login host.
const defaultDomain = "login.salesforce.com"

// New returns an OAuth2 strategy for Salesforce using the production login host
// ("login.salesforce.com"). Use NewWithDomain to target a sandbox or My Domain
// host.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Salesforce login host
// (e.g. "login.salesforce.com", "test.salesforce.com" or "your-domain.my.salesforce.com"),
// without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("salesforce", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/services/oauth2/authorize",
		TokenURL:     base + "/services/oauth2/token",
		UserInfoURL:  base + "/services/oauth2/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
