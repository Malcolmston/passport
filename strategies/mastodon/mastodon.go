// Package mastodon provides a passport OAuth2 strategy preset for Mastodon, the
// federated, self-hostable social network. It is a thin wrapper over
// strategies/oauth2 and ports passport-mastodon: New and NewWithDomain return a
// *oauth2.Strategy, so the full OAuth2 base API and its documented semantics
// apply here unchanged.
//
// Use this package to let users log in with a Mastodon account. Because Mastodon
// is not a single service but a federation of independent instances, its OAuth2
// endpoints are derived from an instance host rather than being fixed. Prefer
// NewWithDomain, which builds the endpoints from the instance host you supply
// (for example "mastodon.social", without a scheme); New exists for convenience
// and uses a placeholder instance you will usually want to override. Register an
// application on the target instance to obtain its client credentials.
//
// The flow is the standard OAuth2 authorization-code grant handled by the base
// package: a login request with no "code" redirects the browser to the
// instance's /oauth/authorize endpoint, and the instance redirects back to your
// callback with a code that is exchanged at /oauth/token and used to fetch the
// account from /api/v1/accounts/verify_credentials.
//
// The default scope is "read", the minimum needed to read the authenticated
// account; request more only if your application acts on the user's behalf. The
// verify_credentials response carries the account "id", which the base package
// uses for Profile.ID, along with "username" and "acct" (the fully-qualified,
// instance-including handle) on Profile.Raw. As with every OAuth2 strategy here,
// "state" is passed through for CSRF protection but owned by the surrounding
// passport middleware, and PKCE is not used.
//
// The verify contract mirrors Passport.js: return a non-nil user to establish
// the session, a nil user (with nil error) to reject the login as an HTTP 401
// failure, or a non-nil error for an internal failure. Compared with the Node
// passport-mastodon, this port exposes the raw account map on Profile.Raw and
// leaves profile normalization to your verify function.
package mastodon

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultInstance is a placeholder Mastodon instance host.
const defaultInstance = "mastodon.social"

// New returns an OAuth2 strategy for Mastodon using the placeholder instance.
// Prefer NewWithDomain to target your actual instance.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultInstance, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Mastodon instance host
// (e.g. "mastodon.social"), without scheme.
func NewWithDomain(instance, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + instance
	return oauth2.New("mastodon", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/oauth/authorize",
		TokenURL:     base + "/oauth/token",
		UserInfoURL:  base + "/api/v1/accounts/verify_credentials",
		Scopes:       []string{"read"},
	}, verify)
}
