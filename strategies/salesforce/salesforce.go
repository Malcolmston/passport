// Package salesforce provides a passport OAuth2 strategy preset for Salesforce.
// Salesforce authenticates against a login host, which is login.salesforce.com
// for production orgs and test.salesforce.com (or a My Domain host) otherwise.
// New uses the production login host; use NewWithDomain to target another host.
package salesforce

import "github.com/malcolmston/passport/strategies/oauth2"

// defaultDomain is the production Salesforce login host.
const defaultDomain = "login.salesforce.com"

// New returns an OAuth2 strategy for Salesforce using the production login host
// ("login.salesforce.com"). Use NewWithDomain to target a sandbox or My Domain
// host.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return NewWithDomain(defaultDomain, clientID, clientSecret, redirectURL, verify)
}

// NewWithDomain returns an OAuth2 strategy for the given Salesforce login host
// (e.g. "login.salesforce.com", "test.salesforce.com" or "your-domain.my.salesforce.com"),
// without scheme.
func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	base := "https://" + domain
	return oauth2.New("salesforce", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      base + "/services/oauth2/authorize",
		TokenURL:     base + "/services/oauth2/token",
		UserInfoURL:  base + "/services/oauth2/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}, verify)
}
