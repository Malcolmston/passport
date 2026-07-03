// Package saml implements a minimal Service Provider handler for a SAML 2.0
// Web Browser SSO POST binding: it reads a base64-encoded SAMLResponse form
// field, decodes it, and extracts the asserted subject (NameID).
//
// SIMPLIFIED / INSECURE FOR PRODUCTION: this package performs NO signature
// validation, NO assertion decryption, NO audience/recipient/timestamp
// checking, and NO replay protection. A real SAML SP MUST verify the XML
// digital signature on the response or assertion before trusting any of its
// contents. This implementation exists only for wiring, local development, and
// tests; do not use it to make real authorization decisions.
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
