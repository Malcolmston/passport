// Package keycloak provides a passport OAuth2 strategy preset for Keycloak.
// Keycloak is self-hosted and realm-scoped: endpoints are built from the host
// and realm. New uses placeholder values; use NewWithRealm to supply your real
// host and realm.
package keycloak

import "github.com/malcolmston/passport/strategies/oauth2"

const (
	defaultHost  = "keycloak.example.com"
	defaultRealm = "master"
)

// New returns an OAuth2 strategy for Keycloak using placeholder host and realm.
// Prefer NewWithRealm to target your actual server and realm.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithRealm(defaultHost, defaultRealm, clientID, clientSecret, redirectURL, verify)
}

// NewWithRealm returns an OAuth2 strategy for the given Keycloak host
// (e.g. "keycloak.example.com", without scheme) and realm.
func NewWithRealm(host, realm, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + host + "/realms/" + realm + "/protocol/openid-connect"
	return oauth2.New("keycloak", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/auth",
		TokenURL:     base + "/token",
		UserInfoURL:  base + "/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
