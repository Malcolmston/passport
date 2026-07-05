// Package cognito provides a passport OAuth2/OIDC strategy preset for signing
// users in through an Amazon Cognito user pool's hosted UI. It corresponds to
// the passport-oauth2 / passport-amazon-cognito-oauth2 strategies used with
// Passport.js and is a thin wrapper over the shared strategies/oauth2 engine.
// Because every Cognito user pool is served from its own domain, the endpoints
// cannot be hard-coded: New uses a placeholder domain for quick experiments,
// while NewWithDomain targets your real hosted-UI domain.
//
// Reach for this strategy when your identities live in Cognito -- for example an
// AWS-centric application that federates Google, Apple, SAML, or username and
// password logins behind a single user pool. The default scopes are the OIDC set
// "openid", "email", and "profile", which return a stable subject (sub) plus the
// user's email and basic profile claims from the pool's /oauth2/userInfo
// endpoint.
//
// Authentication is the OAuth2 authorization-code grant. The initiation route
// (no ?code=) redirects the browser to https://<domain>/oauth2/authorize with
// your client_id, redirect_uri, response_type=code, and scopes. Cognito
// authenticates the user, then redirects back to your callback route with
// ?code=; the strategy exchanges that code at /oauth2/token, calls
// /oauth2/userInfo with the bearer token, and assembles an oauth2.Profile
// (Provider "cognito", ID taken from the sub claim, the raw claim map, and the
// access token).
//
// The Profile is passed to your VerifyFunc, which decides the outcome: a non-nil
// user establishes the session, a nil user with a nil error is an authentication
// failure (HTTP 401), and a non-nil error is an internal error. State from the
// initiation request's ?state= parameter is forwarded to Cognito and echoed
// back, but this port neither generates nor validates it, and it does not
// implement PKCE; add both in your own initiation handler when you need CSRF and
// public-client protection.
//
// Parity with Passport.js: the strategy registers under the name "cognito" and
// mirrors the hosted-UI endpoint layout, but the normalized profile is
// deliberately minimal (id/sub, raw map, access token) rather than the richer
// profile object the Node strategies build, and extras such as refresh-token
// rotation and token expiry are parsed by the oauth2 base but not persisted for
// you. Store any additional claims you need from Profile.Raw inside your verify
// function.
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
