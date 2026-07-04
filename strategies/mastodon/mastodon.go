// Package mastodon provides a passport OAuth2 strategy preset for Mastodon.
// Mastodon is instance-based: endpoints are built from the instance host. New
// uses a placeholder instance; use NewWithDomain to supply your real instance.
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
