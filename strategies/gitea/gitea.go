// Package gitea provides a passport OAuth2 strategy preset for Gitea. Gitea is
// self-hosted: endpoints are built from the instance host. New uses a
// placeholder host; use NewWithDomain to supply your real host.
package gitea

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultHost is a placeholder Gitea host.
const defaultHost = "gitea.example.com"

// New returns an OAuth2 strategy for Gitea using the placeholder host. Prefer
// NewWithDomain to target your actual instance.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultHost, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Gitea host
// (e.g. "gitea.example.com"), without scheme.
func NewWithDomain(host, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + host
	return oauth2.New("gitea", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/login/oauth/authorize",
		TokenURL:     base + "/login/oauth/access_token",
		UserInfoURL:  base + "/api/v1/user",
	}, verify)
}
