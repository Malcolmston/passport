// Package oauth1twitter is a thin wrapper over strategies/oauth1 that presets
// Twitter's OAuth 1.0a endpoints. It exists so applications can authenticate
// with Twitter without repeating the request-token, authorize, and access-token
// URLs. It ports passport-twitter's OAuth 1.0a mode: New returns a *oauth1.
// Strategy registered under the name "twitter", so it is a provider preset over
// the shared OAuth 1.0a base rather than a reimplementation of it.
//
// Use this package when you want "Sign in with Twitter" over the classic
// OAuth 1.0a (HMAC-SHA1) protocol. Construct a Config with your Twitter
// application consumer key and secret plus the CallbackURL you registered in the
// Twitter developer portal, pass it to New along with a verify function, and
// register the returned strategy with passport under the name "twitter".
//
// The flow is the three-legged OAuth 1.0a dance implemented by strategies/oauth1.
// On the first request (no oauth_verifier) the strategy fetches a request token
// from Twitter's request-token endpoint and redirects the browser to the
// authorize endpoint; Twitter authenticates the user and redirects back to
// CallbackURL with an oauth_verifier, which the strategy exchanges at the
// access-token endpoint for the user's access token and secret. Those, along
// with the raw token-endpoint parameters (which include user_id and
// screen_name), are handed to the VerifyFunc.
//
// Because the endpoints are fixed constants, the only inputs are your
// credentials and callback URL; everything about signing, nonces, timestamps,
// and percent-encoding is inherited from the base package. Note the same
// SIMPLIFIED caveat documented on strategies/oauth1: the access-token exchange
// is signed with an empty token secret, so a production deployment that needs
// the request-token secret carried across the redirect must add that session
// plumbing itself.
//
// The verify contract matches the rest of this port and passport-twitter:
// return a non-nil user to establish the session, return a nil user with a nil
// error to reject the login (an HTTP 401 failure), and return a non-nil error to
// report an internal failure. Compared with the Node passport-twitter this
// wrapper covers only the OAuth 1.0a sign-in path and leaves profile fetching to
// the verify function via the returned token parameters.
package oauth1twitter

import "github.com/malcolmston/passport/strategies/oauth1"

// Twitter's OAuth 1.0a endpoints.
const (
	// RequestTokenURL is Twitter's OAuth 1.0a request-token endpoint.
	RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	// AuthorizeURL is Twitter's OAuth 1.0a user-authorization endpoint.
	AuthorizeURL = "https://api.twitter.com/oauth/authorize"
	// AccessTokenURL is Twitter's OAuth 1.0a access-token endpoint.
	AccessTokenURL = "https://api.twitter.com/oauth/access_token"
)

// Config carries the Twitter application credentials and callback URL.
type Config struct {
	ConsumerKey    string // Twitter application consumer key
	ConsumerSecret string // Twitter application consumer secret
	CallbackURL    string // URL Twitter redirects back to after authorization
}

// New builds an oauth1.Strategy named "twitter" wired to Twitter's endpoints.
func New(cfg Config, verify oauth1.VerifyFunc) *oauth1.Strategy {
	return oauth1.New("twitter", oauth1.Config{
		ConsumerKey:     cfg.ConsumerKey,
		ConsumerSecret:  cfg.ConsumerSecret,
		RequestTokenURL: RequestTokenURL,
		AuthorizeURL:    AuthorizeURL,
		AccessTokenURL:  AccessTokenURL,
		CallbackURL:     cfg.CallbackURL,
	}, verify)
}
