// Package oauth1twitter is a thin wrapper over strategies/oauth1 that presets
// Twitter's OAuth 1.0a endpoints. It exists so applications can authenticate
// with Twitter without repeating the endpoint URLs.
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
