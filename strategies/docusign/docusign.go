// Package docusign provides a passport OAuth2 strategy preset for DocuSign
// (account.docusign.com production authentication).
package docusign

import "github.com/malcolmston/passport/strategies/oauth2"

// New returns an OAuth2 strategy configured for DocuSign.
func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy {
	return oauth2.New("docusign", oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://account.docusign.com/oauth/auth",
		TokenURL:     "https://account.docusign.com/oauth/token",
		UserInfoURL:  "https://account.docusign.com/oauth/userinfo",
		Scopes:       []string{"signature"},
	}, verify)
}
