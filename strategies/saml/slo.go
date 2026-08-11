package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This file implements the SAML 2.0 Single Logout profile for a service
// provider: validating an IdP-initiated samlp:LogoutRequest and answering it,
// and issuing an SP-initiated LogoutRequest and validating the IdP's
// samlp:LogoutResponse.
//
// The anti-forgery discipline is the same as everywhere else in the package.
// An unsigned logout message is rejected. That matters in both directions:
//
//   - An unauthenticated LogoutRequest lets anyone who knows a NameID terminate
//     that user's session at will, which is a real if low-severity denial of
//     service, and lets an attacker mass-log-out an entire tenant.
//   - An unauthenticated LogoutResponse is worse. It confirms a logout that may
//     never have happened, so an SP that clears local state on "Success" can be
//     tricked into believing the IdP session is gone while it is still live —
//     the user appears logged out and is not.

// Status codes used by the logout profile.
const (
	// StatusRequester indicates the message was rejected because of a problem
	// with the request.
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	// StatusResponder indicates the message was rejected because of a problem
	// at the responder.
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	// StatusPartialLogout indicates some, but not all, sessions were ended.
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
)

// Errors reported by the single logout profile.
var (
	// ErrLogoutStatus is returned when a LogoutResponse carries a StatusCode
	// other than Success.
	ErrLogoutStatus = errors.New("saml: logout response status is not Success")
	// ErrInResponseTo is returned when a LogoutResponse answers a request
	// this service provider did not issue.
	ErrInResponseTo = errors.New("saml: logout response InResponseTo does not match the request")
)

// SLOOptions configures single logout. It is deliberately separate from
// Options: logout uses the SP's own signing key, which the ACS strategy has no
// business holding.
type SLOOptions struct {
	// EntityID is this service provider's entity ID, used as the saml:Issuer
	// of messages this package sends. Required.
	EntityID string

	// IdPEntityID, when set, is the only saml:Issuer accepted on incoming
	// logout messages. Leaving it empty accepts any issuer whose signature
	// verifies, which is safe but less precise.
	IdPEntityID string

	// IdPCertificates are the identity provider's signing certificates, used
	// to verify incoming LogoutRequests and LogoutResponses. Without at least
	// one, every incoming message is rejected.
	IdPCertificates []*x509.Certificate

	// IdPCertificatePEM is an alternative to IdPCertificates accepting
	// concatenated PEM CERTIFICATE blocks. Both may be set; they are merged.
	IdPCertificatePEM []byte

	// SingleLogoutServiceURL is this SP's own SLO endpoint. When set, an
	// incoming message carrying a Destination must name it; when unset, a
	// message carrying a Destination is rejected, exactly as the ACS side
	// treats Recipient and Destination.
	SingleLogoutServiceURL string

	// IdPSingleLogoutServiceURL is the IdP's SLO endpoint, used as the
	// Destination of messages this package sends. Required to send anything.
	IdPSingleLogoutServiceURL string

	// SigningKey is the SP's private key, used to sign outgoing logout
	// messages.
	SigningKey crypto.Signer

	// SigningCertificate is embedded in the POST binding's KeyInfo.
	SigningCertificate *x509.Certificate

	// SignatureAlgorithm is the SignatureMethod URI to sign with. Defaults to
	// RSA-SHA256 or ECDSA-SHA256 according to the key type.
	SignatureAlgorithm string

	// AllowSHA1 permits SHA-1 signatures on *incoming* messages. Outgoing
	// messages are never signed with SHA-1.
	AllowSHA1 bool

	// Clock supplies the current time; nil means time.Now.
	Clock func() time.Time

	// ClockSkew is the tolerance applied to NotOnOrAfter. Defaults to one
	// minute; a negative value disables it.
	ClockSkew time.Duration

	// NewID generates message IDs. Nil means crypto/rand.
	NewID func() (string, error)

	// MaxBytes caps the decoded XML of an incoming message. Defaults to 5 MiB.
	MaxBytes int

	// MaxDepth caps XML nesting. Defaults to 100.
	MaxDepth int

	// InsecureSkipSignatureValidation accepts unsigned logout messages. It
	// exists for local development against a mock IdP and must never be set
	// in production: see the discussion at the top of this file for what an
	// unauthenticated LogoutRequest and LogoutResponse each buy an attacker.
	InsecureSkipSignatureValidation bool
}

// SLO implements the SAML 2.0 Single Logout profile for a service provider. It
// is safe for concurrent use.
type SLO struct {
	opts   SLOOptions
	certs  []*x509.Certificate
	sigAlg string
	skew   time.Duration
}

// NewSLO validates opts and returns a single logout handler.
func NewSLO(opts SLOOptions) (*SLO, error) {
	if opts.EntityID == "" {
		return nil, errors.New("saml: SLOOptions.EntityID is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxResponseBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	s := &SLO{opts: opts, certs: append([]*x509.Certificate(nil), opts.IdPCertificates...)}
	if len(opts.IdPCertificatePEM) > 0 {
		certs, err := ParseCertificates(opts.IdPCertificatePEM)
		if err != nil {
			return nil, err
		}
		s.certs = append(s.certs, certs...)
	}
	s.skew = opts.ClockSkew
	if s.skew == 0 {
		s.skew = defaultClockSkew
	}
	if s.skew < 0 {
		s.skew = 0
	}
	var err error
	if s.sigAlg, err = resolveSigAlg(opts.SignatureAlgorithm, opts.SigningKey); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SLO) now() time.Time {
	if s.opts.Clock != nil {
		return s.opts.Clock()
	}
	return time.Now()
}

func (s *SLO) newID() (string, error) {
	if s.opts.NewID != nil {
		return s.opts.NewID()
	}
	return NewMessageID()
}

// LogoutRequest is a validated samlp:LogoutRequest.
type LogoutRequest struct {
	// ID is the request's ID attribute; a LogoutResponse must quote it as
	// InResponseTo.
	ID string
	// Issuer is the entity that sent the request.
	Issuer string
	// Destination is the endpoint the request was addressed to, empty when
	// the request did not state one.
	Destination string
	// IssueInstant is when the request was issued.
	IssueInstant time.Time
	// NotOnOrAfter is the request's expiry, zero when not stated.
	NotOnOrAfter time.Time
	// NameID is the subject whose sessions are to be terminated.
	NameID string
	// NameIDFormat is the Format attribute of the NameID, if present.
	NameIDFormat string
	// NameQualifier and SPNameQualifier qualify the NameID, if present.
	NameQualifier, SPNameQualifier string
	// SessionIndex is the first SessionIndex in the request, empty when the
	// request names none (meaning "all sessions for this subject").
	SessionIndex string
	// SessionIndexes holds every SessionIndex in the request.
	SessionIndexes []string
	// Reason is the request's Reason attribute, if present.
	Reason string
	// RelayState is the RelayState that accompanied the request; it must be
	// echoed back on the response.
	RelayState string
	// Signed reports whether the request carried a verified signature. It is
	// only ever false when InsecureSkipSignatureValidation is set.
	Signed bool
}

// LogoutResponse is a validated samlp:LogoutResponse.
type LogoutResponse struct {
	// ID is the response's own ID.
	ID string
	// InResponseTo is the ID of the LogoutRequest being answered.
	InResponseTo string
	// Issuer is the entity that sent the response.
	Issuer string
	// Destination is the endpoint the response was addressed to.
	Destination string
	// IssueInstant is when the response was issued.
	IssueInstant time.Time
	// StatusCode is the top-level samlp:StatusCode Value.
	StatusCode string
	// StatusMessage is the samlp:StatusMessage, if present.
	StatusMessage string
	// RelayState is the RelayState that accompanied the response.
	RelayState string
	// Signed reports whether the response carried a verified signature.
	Signed bool
}

// Message is a protocol message this package produced, ready to be handed to
// one of the bindings.
type Message struct {
	// ID is the message's ID attribute. For a LogoutRequest, persist it so
	// the matching LogoutResponse can be checked against it.
	ID string
	// InResponseTo is set on responses.
	InResponseTo string
	// Field is the binding parameter name: "SAMLRequest" or "SAMLResponse".
	Field string
	// Destination is the endpoint the message is addressed to.
	Destination string
	// XML is the unsigned message document.
	XML []byte

	// tmpl retains the signature placeholder for the POST binding.
	tmpl string
}

// BuildLogoutRequest constructs an SP-initiated samlp:LogoutRequest for the
// given subject. sessionIndexes may be empty, which asks the IdP to terminate
// every session for the subject.
//
// Persist the returned Message.ID: ValidateLogoutResponse* needs it to reject a
// response that answers some other request.
func (s *SLO) BuildLogoutRequest(nameID, nameIDFormat string, sessionIndexes ...string) (*Message, error) {
	if nameID == "" {
		return nil, errors.New("saml: BuildLogoutRequest needs a NameID")
	}
	if s.opts.IdPSingleLogoutServiceURL == "" {
		return nil, errors.New("saml: SLOOptions.IdPSingleLogoutServiceURL is required to send a logout message")
	}
	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()

	var sb strings.Builder
	sb.WriteString(`<samlp:LogoutRequest xmlns:samlp="` + nsSAMLProtocol + `"`)
	sb.WriteString(` xmlns:saml="` + nsSAMLAssertion + `"`)
	sb.WriteString(` ID="` + escapeAttr(id) + `" Version="2.0"`)
	sb.WriteString(` IssueInstant="` + now.Format(time.RFC3339) + `"`)
	sb.WriteString(` Destination="` + escapeAttr(s.opts.IdPSingleLogoutServiceURL) + `">`)
	sb.WriteString(`<saml:Issuer>` + escapeText(s.opts.EntityID) + `</saml:Issuer>`)
	// Schema order: Issuer, Signature, Extensions, then the identifier.
	sb.WriteString(signatureMarker)
	sb.WriteString(`<saml:NameID`)
	if nameIDFormat != "" {
		sb.WriteString(` Format="` + escapeAttr(nameIDFormat) + `"`)
	}
	sb.WriteString(`>` + escapeText(nameID) + `</saml:NameID>`)
	for _, idx := range sessionIndexes {
		if idx == "" {
			continue
		}
		sb.WriteString(`<samlp:SessionIndex>` + escapeText(idx) + `</samlp:SessionIndex>`)
	}
	sb.WriteString(`</samlp:LogoutRequest>`)

	tmpl := sb.String()
	return &Message{
		ID:          id,
		Field:       "SAMLRequest",
		Destination: s.opts.IdPSingleLogoutServiceURL,
		XML:         []byte(strings.Replace(tmpl, signatureMarker, "", 1)),
		tmpl:        tmpl,
	}, nil
}

// BuildLogoutResponse constructs a Success samlp:LogoutResponse answering req.
// Use BuildLogoutResponseStatus to report a failure instead.
func (s *SLO) BuildLogoutResponse(req *LogoutRequest) (*Message, error) {
	return s.BuildLogoutResponseStatus(req, StatusSuccess, "")
}

// BuildLogoutResponseStatus constructs a samlp:LogoutResponse answering req
// with an explicit top-level status code.
func (s *SLO) BuildLogoutResponseStatus(req *LogoutRequest, statusCode, statusMessage string) (*Message, error) {
	if req == nil || req.ID == "" {
		return nil, errors.New("saml: BuildLogoutResponse needs the request it answers")
	}
	if s.opts.IdPSingleLogoutServiceURL == "" {
		return nil, errors.New("saml: SLOOptions.IdPSingleLogoutServiceURL is required to send a logout message")
	}
	if statusCode == "" {
		statusCode = StatusSuccess
	}
	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()

	var sb strings.Builder
	sb.WriteString(`<samlp:LogoutResponse xmlns:samlp="` + nsSAMLProtocol + `"`)
	sb.WriteString(` xmlns:saml="` + nsSAMLAssertion + `"`)
	sb.WriteString(` ID="` + escapeAttr(id) + `" Version="2.0"`)
	sb.WriteString(` IssueInstant="` + now.Format(time.RFC3339) + `"`)
	sb.WriteString(` Destination="` + escapeAttr(s.opts.IdPSingleLogoutServiceURL) + `"`)
	sb.WriteString(` InResponseTo="` + escapeAttr(req.ID) + `">`)
	sb.WriteString(`<saml:Issuer>` + escapeText(s.opts.EntityID) + `</saml:Issuer>`)
	sb.WriteString(signatureMarker)
	sb.WriteString(`<samlp:Status><samlp:StatusCode Value="` + escapeAttr(statusCode) + `"/>`)
	if statusMessage != "" {
		sb.WriteString(`<samlp:StatusMessage>` + escapeText(statusMessage) + `</samlp:StatusMessage>`)
	}
	sb.WriteString(`</samlp:Status>`)
	sb.WriteString(`</samlp:LogoutResponse>`)

	tmpl := sb.String()
	return &Message{
		ID:           id,
		InResponseTo: req.ID,
		Field:        "SAMLResponse",
		Destination:  s.opts.IdPSingleLogoutServiceURL,
		XML:          []byte(strings.Replace(tmpl, signatureMarker, "", 1)),
		tmpl:         tmpl,
	}, nil
}

// RedirectURL renders m for the HTTP-Redirect binding, signing the query string
// when a signing key is configured.
func (s *SLO) RedirectURL(m *Message, relayState string) (string, error) {
	if m == nil {
		return "", errors.New("saml: nil message")
	}
	return redirectBindingURL(m.Destination, m.Field, m.XML, relayState, s.opts.SigningKey, s.sigAlg)
}

// PostBinding renders m for the HTTP-POST binding with an enveloped XML
// signature. It requires a signing key: an unsigned logout message over the
// POST binding carries no authentication at all.
func (s *SLO) PostBinding(m *Message, relayState string) (*PostBinding, error) {
	if m == nil {
		return nil, errors.New("saml: nil message")
	}
	if s.opts.SigningKey == nil {
		return nil, ErrNoSigningKey
	}
	signed, err := signEnveloped(m.tmpl, m.ID, s.opts.SigningKey, s.opts.SigningCertificate, s.sigAlg, s.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	return &PostBinding{
		URL:        m.Destination,
		Field:      m.Field,
		Value:      base64.StdEncoding.EncodeToString(signed),
		RelayState: relayState,
	}, nil
}

// requireSignature reports whether an incoming message must carry a verified
// signature. It is true unless the caller explicitly opted out.
func (s *SLO) requireSignature() bool { return !s.opts.InsecureSkipSignatureValidation }

// ValidateLogoutRequestPOST validates a base64-encoded samlp:LogoutRequest
// received over the HTTP-POST binding.
func (s *SLO) ValidateLogoutRequestPOST(samlRequestBase64, relayState string) (*LogoutRequest, error) {
	raw, err := s.decodePost(samlRequestBase64)
	if err != nil {
		return nil, err
	}
	root, signed, err := s.parseAndVerify(raw, nsSAMLProtocol, "LogoutRequest")
	if err != nil {
		return nil, err
	}
	req, err := s.readLogoutRequest(root)
	if err != nil {
		return nil, err
	}
	req.Signed = signed
	req.RelayState = relayState
	return req, nil
}

// ValidateLogoutRequestRedirect validates a samlp:LogoutRequest received over
// the HTTP-Redirect binding.
//
// rawQuery must be r.URL.RawQuery — the undecoded query string. Passing a
// re-encoded form of the parameters would break signature verification, and a
// verifier that tolerated it would be exploitable; see redirectSignedString.
func (s *SLO) ValidateLogoutRequestRedirect(rawQuery string) (*LogoutRequest, error) {
	msg, err := parseRedirect(rawQuery, "SAMLRequest", s.certs, s.opts.AllowSHA1, s.requireSignature(), s.opts.MaxBytes)
	if err != nil {
		return nil, err
	}
	root, err := parseXML(msg.xml, s.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	if !root.is(nsSAMLProtocol, "LogoutRequest") {
		return nil, fmt.Errorf("saml: root element is <%s>, expected samlp:LogoutRequest", root.local)
	}
	// A redirect-binding message may also carry an enveloped signature; the
	// binding says it should not, and accepting one would give an attacker a
	// second, differently-scoped way to authenticate the message.
	if err := rejectEnvelopedSignature(root); err != nil {
		return nil, err
	}
	req, err := s.readLogoutRequest(root)
	if err != nil {
		return nil, err
	}
	req.Signed = msg.signed
	req.RelayState = msg.relayState
	return req, nil
}

// ValidateLogoutResponsePOST validates a base64-encoded samlp:LogoutResponse
// received over the HTTP-POST binding. expectedInResponseTo is the ID of the
// LogoutRequest this SP issued and must not be empty: an unsolicited
// LogoutResponse answers nothing and is always a forgery.
func (s *SLO) ValidateLogoutResponsePOST(samlResponseBase64, expectedInResponseTo, relayState string) (*LogoutResponse, error) {
	raw, err := s.decodePost(samlResponseBase64)
	if err != nil {
		return nil, err
	}
	root, signed, err := s.parseAndVerify(raw, nsSAMLProtocol, "LogoutResponse")
	if err != nil {
		return nil, err
	}
	resp, err := s.readLogoutResponse(root, expectedInResponseTo)
	if err != nil {
		return nil, err
	}
	resp.Signed = signed
	resp.RelayState = relayState
	return resp, nil
}

// ValidateLogoutResponseRedirect validates a samlp:LogoutResponse received over
// the HTTP-Redirect binding. rawQuery must be r.URL.RawQuery.
func (s *SLO) ValidateLogoutResponseRedirect(rawQuery, expectedInResponseTo string) (*LogoutResponse, error) {
	msg, err := parseRedirect(rawQuery, "SAMLResponse", s.certs, s.opts.AllowSHA1, s.requireSignature(), s.opts.MaxBytes)
	if err != nil {
		return nil, err
	}
	root, err := parseXML(msg.xml, s.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	if !root.is(nsSAMLProtocol, "LogoutResponse") {
		return nil, fmt.Errorf("saml: root element is <%s>, expected samlp:LogoutResponse", root.local)
	}
	if err := rejectEnvelopedSignature(root); err != nil {
		return nil, err
	}
	resp, err := s.readLogoutResponse(root, expectedInResponseTo)
	if err != nil {
		return nil, err
	}
	resp.Signed = msg.signed
	resp.RelayState = msg.relayState
	return resp, nil
}

// decodePost base64-decodes a POST-binding parameter under the size cap.
func (s *SLO) decodePost(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, errors.New("saml: empty logout message")
	}
	if len(b64)/4*3 > s.opts.MaxBytes {
		return nil, ErrTooLarge
	}
	raw, err := decodeBase64(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) > s.opts.MaxBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// parseAndVerify parses a POST-binding logout message and verifies its
// enveloped signature.
//
// The signature must cover the root element itself. verifySignature returns the
// element the reference actually names, and anything else is refused — a
// signature over some other part of the document proves nothing about the
// message being acted on.
func (s *SLO) parseAndVerify(raw []byte, ns, local string) (*xnode, bool, error) {
	root, err := parseXML(raw, s.opts.MaxDepth)
	if err != nil {
		return nil, false, err
	}
	if !root.is(ns, local) {
		return nil, false, fmt.Errorf("saml: root element is <%s>, expected samlp:%s", root.local, local)
	}

	var signatures []*xnode
	root.walk(func(n *xnode) {
		if n.is(nsDSig, "Signature") {
			signatures = append(signatures, n)
		}
	})
	if len(signatures) == 0 {
		if s.requireSignature() {
			if len(s.certs) == 0 {
				return nil, false, ErrNoCertificates
			}
			return nil, false, ErrNoSignature
		}
		return root, false, nil
	}
	if len(s.certs) == 0 {
		return nil, false, ErrNoCertificates
	}
	// Every signature present must verify and must cover the root. A message
	// with one good and one bad signature is not "signed".
	covered := false
	for _, sig := range signatures {
		if sig.parent != root {
			return nil, false, errors.New("saml: ds:Signature is not a child of the logout message")
		}
		verified, err := verifySignature(root, sig, s.certs, s.opts.AllowSHA1)
		if err != nil {
			return nil, false, err
		}
		if verified.element != root {
			return nil, false, errors.New("saml: signature covers an unexpected element")
		}
		covered = true
	}
	if !covered {
		return nil, false, ErrNoSignature
	}
	return root, true, nil
}

// rejectEnvelopedSignature refuses a redirect-binding message that also carries
// an XML signature. Over the redirect binding the query string is what is
// authenticated; an additional enveloped signature could only serve to make the
// verified and the acted-upon documents differ.
func rejectEnvelopedSignature(root *xnode) error {
	var found bool
	root.walk(func(n *xnode) {
		if n.is(nsDSig, "Signature") {
			found = true
		}
	})
	if found {
		return errors.New("saml: redirect-binding message carries an enveloped XML signature")
	}
	return nil
}

// readLogoutRequest extracts a LogoutRequest and applies the non-signature
// checks: issuer, destination and validity window.
func (s *SLO) readLogoutRequest(root *xnode) (*LogoutRequest, error) {
	req := &LogoutRequest{}
	var ok bool
	if req.ID, ok = root.attrValue("", "ID"); !ok || req.ID == "" {
		return nil, errors.New("saml: LogoutRequest has no ID attribute")
	}
	if v, ok := root.attrValue("", "Version"); ok && v != "2.0" {
		return nil, fmt.Errorf("saml: LogoutRequest Version is %q, expected 2.0", v)
	}
	if v, ok := root.attrValue("", "IssueInstant"); ok {
		var err error
		if req.IssueInstant, err = parseSAMLTime(v); err != nil {
			return nil, err
		}
	}
	if v, ok := root.attrValue("", "NotOnOrAfter"); ok {
		var err error
		if req.NotOnOrAfter, err = parseSAMLTime(v); err != nil {
			return nil, err
		}
	}
	req.Reason, _ = root.attrValue("", "Reason")
	req.Destination, _ = root.attrValue("", "Destination")

	issuer, err := root.optionalChild(nsSAMLAssertion, "Issuer")
	if err != nil {
		return nil, err
	}
	if issuer != nil {
		req.Issuer = strings.TrimSpace(issuer.textContent())
	}

	// Encrypted identifiers are rejected rather than ignored, so a logout for
	// an EncryptedID never silently becomes a logout for nobody.
	if enc, err := root.optionalChild(nsSAMLAssertion, "EncryptedID"); err != nil {
		return nil, err
	} else if enc != nil {
		return nil, ErrEncrypted
	}
	nameID, err := root.onlyChild(nsSAMLAssertion, "NameID")
	if err != nil {
		return nil, err
	}
	req.NameID = strings.TrimSpace(nameID.textContent())
	if req.NameID == "" {
		return nil, ErrNoNameID
	}
	req.NameIDFormat, _ = nameID.attrValue("", "Format")
	req.NameQualifier, _ = nameID.attrValue("", "NameQualifier")
	req.SPNameQualifier, _ = nameID.attrValue("", "SPNameQualifier")

	for _, idx := range root.childElements(nsSAMLProtocol, "SessionIndex") {
		if v := strings.TrimSpace(idx.textContent()); v != "" {
			req.SessionIndexes = append(req.SessionIndexes, v)
		}
	}
	if len(req.SessionIndexes) > 0 {
		req.SessionIndex = req.SessionIndexes[0]
	}

	if err := s.checkIssuer(req.Issuer); err != nil {
		return nil, err
	}
	if err := s.checkDestination(req.Destination); err != nil {
		return nil, err
	}
	if !req.NotOnOrAfter.IsZero() {
		if now := s.now(); !now.Before(req.NotOnOrAfter.Add(s.skew)) {
			return nil, fmt.Errorf("%w: LogoutRequest expired at %s (now %s)", ErrConditions,
				req.NotOnOrAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}
	return req, nil
}

// readLogoutResponse extracts a LogoutResponse and applies the non-signature
// checks: issuer, destination, InResponseTo and status.
func (s *SLO) readLogoutResponse(root *xnode, expectedInResponseTo string) (*LogoutResponse, error) {
	resp := &LogoutResponse{}
	var ok bool
	if resp.ID, ok = root.attrValue("", "ID"); !ok || resp.ID == "" {
		return nil, errors.New("saml: LogoutResponse has no ID attribute")
	}
	if v, ok := root.attrValue("", "Version"); ok && v != "2.0" {
		return nil, fmt.Errorf("saml: LogoutResponse Version is %q, expected 2.0", v)
	}
	if v, ok := root.attrValue("", "IssueInstant"); ok {
		var err error
		if resp.IssueInstant, err = parseSAMLTime(v); err != nil {
			return nil, err
		}
	}
	resp.Destination, _ = root.attrValue("", "Destination")
	resp.InResponseTo, _ = root.attrValue("", "InResponseTo")

	issuer, err := root.optionalChild(nsSAMLAssertion, "Issuer")
	if err != nil {
		return nil, err
	}
	if issuer != nil {
		resp.Issuer = strings.TrimSpace(issuer.textContent())
	}
	status, err := root.onlyChild(nsSAMLProtocol, "Status")
	if err != nil {
		return nil, err
	}
	code, err := status.onlyChild(nsSAMLProtocol, "StatusCode")
	if err != nil {
		return nil, err
	}
	resp.StatusCode, _ = code.attrValue("", "Value")
	if m, err := status.optionalChild(nsSAMLProtocol, "StatusMessage"); err != nil {
		return nil, err
	} else if m != nil {
		resp.StatusMessage = strings.TrimSpace(m.textContent())
	}

	if err := s.checkIssuer(resp.Issuer); err != nil {
		return nil, err
	}
	if err := s.checkDestination(resp.Destination); err != nil {
		return nil, err
	}
	// An unsolicited LogoutResponse is meaningless: it claims to answer a
	// request, so there must be a request to answer.
	if expectedInResponseTo == "" {
		return nil, fmt.Errorf("%w: no LogoutRequest ID to match against", ErrInResponseTo)
	}
	if resp.InResponseTo != expectedInResponseTo {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrInResponseTo, resp.InResponseTo, expectedInResponseTo)
	}
	if resp.StatusCode != StatusSuccess {
		msg := resp.StatusCode
		if resp.StatusMessage != "" {
			msg += ": " + resp.StatusMessage
		}
		return nil, fmt.Errorf("%w (%s)", ErrLogoutStatus, msg)
	}
	return resp, nil
}

func (s *SLO) checkIssuer(got string) error {
	if s.opts.IdPEntityID == "" {
		return nil
	}
	if got != s.opts.IdPEntityID {
		return fmt.Errorf("%w: issuer %q does not match %q", ErrConditions, got, s.opts.IdPEntityID)
	}
	return nil
}

func (s *SLO) checkDestination(got string) error {
	if got == "" {
		return nil
	}
	if s.opts.SingleLogoutServiceURL == "" {
		return errors.New("saml: logout message carries a Destination but SLOOptions.SingleLogoutServiceURL is not configured")
	}
	if got != s.opts.SingleLogoutServiceURL {
		return fmt.Errorf("%w: Destination %q does not match %q", ErrConditions, got, s.opts.SingleLogoutServiceURL)
	}
	return nil
}
