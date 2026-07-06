// Package facebook provides a passport OAuth2 strategy preset for signing users
// in with their Facebook account. It is the Go port of the widely used
// Passport.js passport-facebook strategy and a thin wrapper over the shared
// strategies/oauth2 engine, presetting Facebook's Login dialog, the Graph API
// token endpoint, and the /me userinfo resource so callers supply only their app
// credentials and a verify function.
//
// Use this strategy when you want a "Sign in with Facebook" (Facebook Login) flow
// in a consumer web application. It requests the "email" scope (permission) by
// default and asks the Graph API for the id, name, and email fields; request
// additional permissions such as "public_profile" or "user_friends" through a
// custom oauth2.Strategy, remembering that most permissions require Facebook App
// Review before they work for the public.
//
// The flow is the OAuth2 authorization-code grant. On the initiation route (no
// ?code=) the strategy redirects the browser to the Facebook Login dialog with
// your client_id (app id), redirect_uri, response_type=code, and scopes. Facebook
// authenticates the user and redirects back to your callback route with ?code=;
// the strategy exchanges the code for an access token, calls
// graph.facebook.com/me?fields=id,name,email with the bearer token, and builds an
// oauth2.Profile (Provider "facebook", ID from the response, the raw JSON map,
// and the access token).
//
// The Profile is passed to your VerifyFunc: return a non-nil user to establish
// the session, a nil user with a nil error to reject the login (HTTP 401), or a
// non-nil error for an internal error. Note that email may be absent (a user can
// deny the permission, or the account may have no confirmed email), so handle a
// missing email in your verify function. State is forwarded from the initiation
// request's ?state= parameter but is not generated or validated for you.
//
// Parity with Passport.js: the strategy registers under the name "facebook" and
// pins Graph API v12.0 in its endpoints. Two differences from passport-facebook
// are worth noting: the normalized profile is minimal (id, raw map, access token)
// rather than the structured profile the Node strategy builds, and this port does
// not compute the appsecret_proof parameter that Facebook recommends for
// server-side Graph calls -- add it yourself when calling the Graph API from your
// verify function if your app requires it.
package facebook

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for Facebook. verify maps the fetched
// profile to an application user.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("facebook", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://www.facebook.com/v12.0/dialog/oauth",
		TokenURL:     "https://graph.facebook.com/v12.0/oauth/access_token",
		UserInfoURL:  "https://graph.facebook.com/me?fields=id,name,email",
		Scopes:       []string{"email"},
	}, verify)
}
