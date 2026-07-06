// Package paypal provides a passport OAuth2/OIDC strategy preset for PayPal's
// "Log in with PayPal" (Connect with PayPal) service, porting the
// passport-paypal-oauth wiring from the Passport.js ecosystem. It is a thin
// configuration layer over strategies/oauth2: it fills in PayPal's
// authorization, token and userinfo endpoints so callers only supply their
// client credentials, a redirect URL and a verify function.
//
// Use this preset when you want users to authenticate with their PayPal account
// and, optionally, share basic profile and email information with your app.
// PayPal uses fixed, global endpoints, so a single New call with your client ID
// and secret is all that is required.
//
// The flow has two legs. On the first request the strategy finds no ?code and
// issues a 302 redirect to https://www.paypal.com/signin/authorize, carrying the
// client ID, redirect URI, requested scopes and an opaque state value. PayPal
// then redirects the browser back to the callback route with a ?code; the
// strategy exchanges that code at the token endpoint for an access token and
// calls the identity userinfo endpoint to fetch the profile. Mount one route for
// the redirect leg and one for the callback, both wired to the "paypal"
// strategy.
//
// The default scopes are "openid", "email" and "profile", which correspond to
// PayPal's OpenID Connect attributes. The state parameter should be a
// per-session random value used for CSRF protection; the surrounding passport
// session machinery round-trips it. The verify function receives the fetched
// oauth2.Profile and maps it to your application user; returning a nil user
// (with a nil error) rejects the login, while a non-nil error surfaces as an
// authentication error.
//
// Parity note: this preset targets PayPal's production hosts. To integrate
// against the PayPal sandbox you would point the endpoints at the sandbox
// domains; like the Node original, this preset presets endpoints and default
// scopes only and does not itself validate the returned id_token.
package paypal

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for PayPal. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("paypal", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.paypal.com/signin/authorize",
		TokenURL:     "https://api-m.paypal.com/v1/oauth2/token",
		UserInfoURL:  "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
