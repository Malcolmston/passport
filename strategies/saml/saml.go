// Package saml implements a minimal SAML 2.0 Service Provider (SP) handler for
// the Web Browser SSO Profile using the HTTP POST binding. It ports the
// server-side shape of passport-saml from the Passport.js ecosystem: it reads a
// base64-encoded SAMLResponse form field posted by the identity provider,
// decodes it, extracts the asserted subject (the NameID), and maps that subject
// to an application user.
//
// Use this strategy when you integrate with an enterprise SAML identity provider
// (Okta, OneLogin, ADFS, Azure AD, Shibboleth, ...) for single sign-on. SAML is
// the incumbent enterprise SSO protocol; reach for it when a customer requires
// SAML rather than OpenID Connect. If you get to choose, OIDC
// (strategies/openidconnect) is generally simpler for new integrations.
//
// The flow is SP-initiated (or IdP-initiated) SSO. In the SP-initiated case the
// user starts at your app, which redirects the browser to the IdP's SSO endpoint
// with an AuthnRequest. The IdP authenticates the user and then POSTs a signed
// SAMLResponse (an auto-submitting HTML form) to your Assertion Consumer Service
// (ACS) endpoint. This strategy is the ACS handler: on that POST it pulls the
// configured form field (Options.Field, default "SAMLResponse"), base64-decodes
// it (accepting both standard and raw/unpadded encodings), and walks the XML for
// any element whose local name is "NameID", regardless of namespace prefix.
// ExtractNameID exposes that decoding step directly. A missing field is a 401
// failure ("missing SAMLResponse"); a field that decodes but yields no NameID
// (ErrNoNameID) is a 401 failure ("invalid SAMLResponse").
//
// The Options.Verify function maps the extracted NameID (often an email or a
// persistent opaque identifier) to your application user. When Verify is nil the
// NameID string is used as the user directly. Returning a nil user (with a nil
// error) rejects the login as a 401 failure, while a non-nil error is reported
// as an internal error. Because SAML users are typically persisted across
// requests, pair this strategy with passport SerializeUser/DeserializeUser so the
// session survives, as the package example shows.
//
// SIMPLIFIED / INSECURE FOR PRODUCTION: unlike the Node original, this package
// performs NO XML digital signature validation, NO assertion decryption, NO
// audience/recipient/destination checking, NO NotBefore/NotOnOrAfter timestamp
// validation, and NO replay (assertion-ID) protection. A real SAML SP MUST
// verify the enveloped XML signature on the response or assertion against the
// IdP's certificate before trusting any of its contents, or an attacker can
// forge a SAMLResponse for any NameID. This implementation exists only for
// wiring, local development, and tests; do not use it to make real authorization
// decisions.
package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrNoNameID is returned when the decoded response contains no NameID.
var ErrNoNameID = errors.New("saml: no NameID found in response")

// VerifyFunc maps an extracted NameID to an application user. When nil, the
// NameID string is used as the user.
type VerifyFunc func(nameID string) (user any, err error)

// Options configures the strategy.
type Options struct {
	// Field is the form field carrying the base64 response. Defaults to
	// "SAMLResponse".
	Field string
	// Verify maps the NameID to a user. Optional.
	Verify VerifyFunc
}

// Strategy consumes a SAMLResponse and authenticates the subject.
type Strategy struct {
	field  string
	verify VerifyFunc
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	field := opts.Field
	if field == "" {
		field = "SAMLResponse"
	}
	return &Strategy{field: field, verify: opts.Verify}
}

// Name returns "saml".
func (s *Strategy) Name() string { return "saml" }

// ExtractNameID base64-decodes a SAMLResponse and returns the NameID text. It
// accepts both standard and raw (unpadded) base64.
func ExtractNameID(b64 string) (string, error) {
	raw, err := decodeBase64(b64)
	if err != nil {
		return "", err
	}
	// Walk the XML looking for any element whose local name is "NameID",
	// regardless of namespace prefix (saml:NameID, NameID, ...).
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "NameID" {
			continue
		}
		var text string
		if err := dec.DecodeElement(&text, &start); err != nil {
			return "", err
		}
		text = strings.TrimSpace(text)
		if text != "" {
			return text, nil
		}
	}
	return "", ErrNoNameID
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	_ = r.ParseForm()
	b64 := r.PostFormValue(s.field)
	if b64 == "" {
		b64 = r.FormValue(s.field)
	}
	if b64 == "" {
		c.Fail("missing SAMLResponse", http.StatusUnauthorized)
		return
	}

	nameID, err := ExtractNameID(b64)
	if err != nil {
		c.Fail("invalid SAMLResponse", http.StatusUnauthorized)
		return
	}

	if s.verify != nil {
		user, err := s.verify(nameID)
		if err != nil {
			c.Error(err)
			return
		}
		if user == nil {
			c.Fail("", http.StatusUnauthorized)
			return
		}
		c.Success(user)
		return
	}
	c.Success(nameID)
}
