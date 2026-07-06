// Package apple provides an OAuth2 "Sign in with Apple" authentication strategy for the
// passport port. It is the Go equivalent of the passport-apple strategy for
// Passport.js and authenticates users against Apple's public OAuth2
// endpoints. The package is a thin preset over the shared strategies/oauth2
// engine, presetting Apple's authorization endpoint (https://appleid.apple.com/auth/authorize),
// token endpoint (https://appleid.apple.com/auth/token) and (deliberately) no userinfo endpoint, because Apple returns identity claims inside the id_token rather than from a profile API.
//
// Use this strategy when you want visitors to sign in with their existing
// Apple account instead of a local username and password. It suits privacy-conscious consumer apps and satisfies App Store rules that require an Apple sign-in option wherever other social logins are offered. Because it
// is a preset over the generic OAuth2 strategy, everything the base engine
// supports (a custom HTTP client, state handling and the verify contract) is
// available here too.
//
// The flow is the standard OAuth2 authorization-code grant, driven entirely by
// the returned *oauth2.Strategy. On the initiation route there is no ?code=
// query parameter, so Authenticate redirects the browser to Apple's
// authorization page with the client ID, redirect URI, requested scopes and
// optional state. After the user approves, Apple redirects back to the
// callback route with a ?code=; the strategy exchanges that code for an access
// token at the token endpoint, and, because Apple publishes no userinfo endpoint, skips the profile fetch, and invokes the verify function
// with the resulting profile.
//
// The default scopes are "name" and "email". Since Apple has no userinfo endpoint the oauth2.Profile.Raw map is empty, and the identity details Apple only returns on the very first authorization must be decoded by the caller from the returned id_token. The oauth2.Profile handed to verify carries the provider name
// ("apple"), the provider-specific ID, the decoded response in Raw, and the
// AccessToken. For CSRF protection the caller should generate a state value,
// pass it on the initiation URL's ?state= query, and validate it on the
// callback. A verify function that returns a nil user with a nil error is
// treated as an authentication failure, while a non-nil error is surfaced as an
// internal server error.
//
// Parity: like passport-apple this exchanges an authorization code and loads the Apple
// profile, but the Go port normalizes the result into an oauth2.Profile rather
// than the Node "profile" object, and it leaves session establishment, user
// serialization and route wiring to the surrounding passport.Passport instance.
// Note that Apple requires the client secret to be a short-lived ES256 JWT signed with your key and expects a form_post response mode; this preset passes the client-secret string through verbatim, so minting/rotating that JWT and handling the form_post callback are left to the caller.
package apple

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Apple. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("apple", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://appleid.apple.com/auth/authorize",
		TokenURL:     "https://appleid.apple.com/auth/token",
		UserInfoURL:  "",
		Scopes:       []string{"name", "email"},
	}, verify)
}
