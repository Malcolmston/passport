// Package oauth1twitter is a thin wrapper over strategies/oauth1 that presets
// Twitter's OAuth 1.0a endpoints. It exists so applications can authenticate
// with Twitter without repeating the endpoint URLs.
package oauth1twitter

import "github.com/malcolmston/passport/strategies/oauth1"

// Twitter's OAuth 1.0a endpoints.
const (
	RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	AuthorizeURL    = "https://api.twitter.com/oauth/authorize"
	AccessTokenURL  = "https://api.twitter.com/oauth/access_token"
)

// Config carries the Twitter application credentials and callback URL.
type Config struct {
	ConsumerKey    string
	ConsumerSecret string
	CallbackURL    string
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
