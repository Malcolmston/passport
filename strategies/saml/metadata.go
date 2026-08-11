package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// This file parses SAML 2.0 metadata so that an identity provider's
// certificates and endpoints can be configured from the document the IdP
// publishes rather than by hand.
//
// # Trust
//
// Metadata is fetched from a remote party, so it is parsed with the same
// hardened parser a SAMLResponse gets: DOCTYPE and entity declarations are
// refused outright, nesting is capped, and the document size is capped before
// anything is allocated for it.
//
// Verifying the metadata signature is what makes the document trustworthy.
// Supply MetadataOptions.TrustAnchors (the certificate the federation or the
// IdP signs its metadata with) and ParseIdPMetadata will require a valid
// signature over the descriptor it returns.
//
// WITHOUT a trust anchor, parsing is trust-on-first-use: whatever the document
// says becomes the set of keys that can then authenticate users. Anyone able to
// alter the document in transit or at rest can substitute their own signing
// certificate and thereafter mint assertions for any user. Unsigned metadata
// must therefore be fetched over HTTPS from a URL you verified out of band, and
// pinned or reviewed before it is used. Re-fetching unsigned metadata
// automatically turns a single successful man-in-the-middle into a permanent
// compromise.

// nsMetadata is the SAML 2.0 metadata namespace.
const nsMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"

// Errors reported by metadata parsing.
var (
	// ErrNoEntityDescriptor is returned when the document contains no
	// md:EntityDescriptor, or none matching MetadataOptions.EntityID.
	ErrNoEntityDescriptor = errors.New("saml: no matching md:EntityDescriptor in metadata")
	// ErrNoIDPDescriptor is returned when the entity has no
	// md:IDPSSODescriptor.
	ErrNoIDPDescriptor = errors.New("saml: entity has no md:IDPSSODescriptor")
	// ErrNoSSOService is returned when the IdP publishes no
	// md:SingleSignOnService endpoint, which makes the metadata unusable.
	ErrNoSSOService = errors.New("saml: IdP metadata has no md:SingleSignOnService endpoint")
	// ErrNoSigningCertificate is returned when the IdP publishes no signing
	// KeyDescriptor. Without one no assertion from it could ever be verified.
	ErrNoSigningCertificate = errors.New("saml: IdP metadata has no signing certificate")
	// ErrMetadataExpired is returned when the descriptor's validUntil is in
	// the past.
	ErrMetadataExpired = errors.New("saml: metadata has expired")
)

// Endpoint is a metadata endpoint: an md:SingleSignOnService,
// md:SingleLogoutService or md:AssertionConsumerService.
type Endpoint struct {
	// Binding is the SAML binding URI, e.g. BindingHTTPRedirect.
	Binding string
	// Location is the URL messages are sent to.
	Location string
	// ResponseLocation, when non-empty, is where the *response* to a message
	// sent to Location must go instead. It is used by single logout.
	ResponseLocation string
	// Index is the endpoint's index attribute, -1 when absent.
	Index int
	// IsDefault reports the isDefault attribute.
	IsDefault bool
}

// IdPMetadata is the parsed content of an identity provider's
// md:IDPSSODescriptor.
type IdPMetadata struct {
	// EntityID is the IdP's entity ID. Assertions it issues name it as their
	// saml:Issuer.
	EntityID string
	// SigningCertificates are the certificates the IdP signs with, in
	// document order. More than one is normal during a key rollover; pass all
	// of them to Options.IdPCertificates.
	SigningCertificates []*x509.Certificate
	// EncryptionCertificates are the certificates an SP should encrypt to.
	// This package does not perform encryption; they are parsed for
	// completeness.
	EncryptionCertificates []*x509.Certificate
	// SingleSignOnServices are the SSO endpoints, in document order.
	SingleSignOnServices []Endpoint
	// SingleLogoutServices are the SLO endpoints, in document order.
	SingleLogoutServices []Endpoint
	// ArtifactResolutionServices are the md:ArtifactResolutionService
	// endpoints, in document order. They are the SOAP back-channel endpoints
	// the HTTP-Artifact binding resolves against; see
	// ApplyToArtifactOptions.
	ArtifactResolutionServices []Endpoint
	// NameIDFormats are the NameID formats the IdP supports.
	NameIDFormats []string
	// WantAuthnRequestsSigned reports the descriptor's
	// WantAuthnRequestsSigned attribute. When true, configure
	// RequestOptions.SigningKey.
	WantAuthnRequestsSigned bool
	// ValidUntil is the descriptor's validUntil, zero when absent.
	ValidUntil time.Time
	// CacheDuration is the parsed cacheDuration attribute. Its zero value
	// means the attribute was absent; XSDuration.Present reports which.
	//
	// It is an XSDuration rather than a time.Duration because xs:duration has
	// no lossless time.Duration representation: a month is not a fixed number
	// of seconds. XSDuration.AddTo applies it correctly, XSDuration.Raw
	// round-trips the original lexical form, and
	// XSDuration.ApproximateDuration is available when an approximation is
	// genuinely what is wanted.
	CacheDuration XSDuration
	// Signed reports whether the metadata carried a signature that was
	// verified against MetadataOptions.TrustAnchors. It is false for
	// trust-on-first-use metadata, including metadata that carried a
	// signature no anchor was supplied for.
	Signed bool
}

// MetadataOptions configures ParseIdPMetadata.
type MetadataOptions struct {
	// EntityID selects one entity from an md:EntitiesDescriptor containing
	// several. When empty, a document must describe exactly one entity.
	EntityID string

	// TrustAnchors are the certificates the metadata signature must verify
	// against. When non-empty a valid signature is REQUIRED; when empty, any
	// signature present is ignored and the result is trust-on-first-use.
	TrustAnchors []*x509.Certificate

	// TrustAnchorPEM is an alternative to TrustAnchors accepting
	// concatenated PEM CERTIFICATE blocks. Both may be set; they are merged.
	TrustAnchorPEM []byte

	// AllowSHA1 permits a SHA-1 metadata signature. Off by default.
	AllowSHA1 bool

	// Now supplies the current time for the validUntil check; nil means
	// time.Now.
	Now func() time.Time

	// SkipValidUntil disables the validUntil check. Expired metadata is
	// rejected by default.
	SkipValidUntil bool

	// MaxBytes caps the document size. Defaults to 5 MiB.
	MaxBytes int

	// MaxDepth caps XML nesting. Defaults to 100.
	MaxDepth int
}

// ParseIdPMetadata parses an md:EntityDescriptor or md:EntitiesDescriptor and
// returns the identity provider role it describes.
//
// See the trust discussion at the top of this file: supply
// MetadataOptions.TrustAnchors whenever the publisher signs its metadata, and
// treat an unsigned document as configuration you have to protect yourself.
func ParseIdPMetadata(data []byte, opts MetadataOptions) (*IdPMetadata, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxResponseBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if len(data) > opts.MaxBytes {
		return nil, ErrTooLarge
	}
	anchors := append([]*x509.Certificate(nil), opts.TrustAnchors...)
	if len(opts.TrustAnchorPEM) > 0 {
		certs, err := ParseCertificates(opts.TrustAnchorPEM)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, certs...)
	}

	root, err := parseXML(data, opts.MaxDepth)
	if err != nil {
		return nil, err
	}

	entity, err := selectEntity(root, opts.EntityID)
	if err != nil {
		return nil, err
	}

	signed := false
	if len(anchors) > 0 {
		if signed, err = verifyMetadataSignature(root, entity, anchors, opts.AllowSHA1); err != nil {
			return nil, err
		}
	}

	m := &IdPMetadata{Signed: signed}
	m.EntityID, _ = entity.attrValue("", "entityID")
	if m.EntityID == "" {
		return nil, errors.New("saml: md:EntityDescriptor has no entityID attribute")
	}

	idp, err := entity.optionalChild(nsMetadata, "IDPSSODescriptor")
	if err != nil {
		return nil, err
	}
	if idp == nil {
		return nil, ErrNoIDPDescriptor
	}
	if v, ok := idp.attrValue("", "WantAuthnRequestsSigned"); ok {
		m.WantAuthnRequestsSigned = v == "true" || v == "1"
	}
	// validUntil and cacheDuration may sit on either the descriptor or the
	// entity; the nearer one wins.
	for _, n := range []*xnode{idp, entity} {
		if m.ValidUntil.IsZero() {
			if v, ok := n.attrValue("", "validUntil"); ok {
				if m.ValidUntil, err = parseSAMLTime(v); err != nil {
					return nil, err
				}
			}
		}
		if !m.CacheDuration.Present() {
			if v, ok := n.attrValue("", "cacheDuration"); ok {
				// A malformed duration is an error, never a silent zero:
				// treating "P1Y" typoed as "1Y" as "do not cache" would be a
				// quiet behaviour change driven by a remote document.
				if m.CacheDuration, err = ParseXSDuration(v); err != nil {
					return nil, err
				}
			}
		}
	}
	if !opts.SkipValidUntil && !m.ValidUntil.IsZero() {
		now := time.Now()
		if opts.Now != nil {
			now = opts.Now()
		}
		if !now.Before(m.ValidUntil) {
			return nil, fmt.Errorf("%w at %s", ErrMetadataExpired, m.ValidUntil.Format(time.RFC3339))
		}
	}

	if m.SigningCertificates, m.EncryptionCertificates, err = keyDescriptors(idp); err != nil {
		return nil, err
	}
	if len(m.SigningCertificates) == 0 {
		return nil, ErrNoSigningCertificate
	}
	if m.SingleSignOnServices, err = endpoints(idp, "SingleSignOnService"); err != nil {
		return nil, err
	}
	if len(m.SingleSignOnServices) == 0 {
		return nil, ErrNoSSOService
	}
	if m.SingleLogoutServices, err = endpoints(idp, "SingleLogoutService"); err != nil {
		return nil, err
	}
	if m.ArtifactResolutionServices, err = endpoints(idp, "ArtifactResolutionService"); err != nil {
		return nil, err
	}
	for _, f := range idp.childElements(nsMetadata, "NameIDFormat") {
		if v := strings.TrimSpace(f.textContent()); v != "" {
			m.NameIDFormats = append(m.NameIDFormats, v)
		}
	}
	return m, nil
}

// selectEntity finds the md:EntityDescriptor to read, from either a bare
// descriptor or an md:EntitiesDescriptor aggregate.
func selectEntity(root *xnode, entityID string) (*xnode, error) {
	var candidates []*xnode
	switch {
	case root.is(nsMetadata, "EntityDescriptor"):
		candidates = []*xnode{root}
	case root.is(nsMetadata, "EntitiesDescriptor"):
		// Only direct children, so a nested aggregate cannot smuggle an
		// entity in under a signature that does not cover it.
		candidates = root.childElements(nsMetadata, "EntityDescriptor")
	default:
		return nil, fmt.Errorf("saml: metadata root is <%s>, expected md:EntityDescriptor or md:EntitiesDescriptor", root.local)
	}
	if entityID != "" {
		var matched []*xnode
		for _, c := range candidates {
			if v, _ := c.attrValue("", "entityID"); v == entityID {
				matched = append(matched, c)
			}
		}
		if len(matched) != 1 {
			return nil, fmt.Errorf("%w: %d entities match %q", ErrNoEntityDescriptor, len(matched), entityID)
		}
		return matched[0], nil
	}
	if len(candidates) != 1 {
		return nil, fmt.Errorf("%w: document describes %d entities, set MetadataOptions.EntityID to pick one",
			ErrNoEntityDescriptor, len(candidates))
	}
	return candidates[0], nil
}

// verifyMetadataSignature requires a signature covering either the selected
// entity descriptor or the aggregate that contains it.
func verifyMetadataSignature(root, entity *xnode, anchors []*x509.Certificate, allowSHA1 bool) (bool, error) {
	var signatures []*xnode
	root.walk(func(n *xnode) {
		if n.is(nsDSig, "Signature") {
			signatures = append(signatures, n)
		}
	})
	if len(signatures) == 0 {
		return false, ErrNoSignature
	}
	covered := false
	for _, sig := range signatures {
		// A signature is only considered when it envelops the aggregate or
		// the entity being read; one buried elsewhere in the document proves
		// nothing about either and is ignored rather than trusted.
		if sig.parent != root && sig.parent != entity {
			continue
		}
		verified, err := verifySignature(root, sig, anchors, allowSHA1)
		if err != nil {
			return false, err
		}
		if verified.element == root || verified.element == entity {
			covered = true
		}
	}
	if !covered {
		return false, fmt.Errorf("%w: no signature covers the selected md:EntityDescriptor", ErrNoSignature)
	}
	return true, nil
}

// keyDescriptors collects the certificates from a role descriptor's
// md:KeyDescriptor elements. A KeyDescriptor with no "use" attribute is valid
// for both signing and encryption, per the metadata schema.
func keyDescriptors(role *xnode) (signing, encryption []*x509.Certificate, err error) {
	for _, kd := range role.childElements(nsMetadata, "KeyDescriptor") {
		use, _ := kd.attrValue("", "use")
		if use != "" && use != "signing" && use != "encryption" {
			return nil, nil, fmt.Errorf("saml: md:KeyDescriptor has unknown use %q", use)
		}
		var certs []*x509.Certificate
		var certErr error
		kd.walk(func(n *xnode) {
			if certErr != nil || !n.is(nsDSig, "X509Certificate") {
				return
			}
			der, err := decodeXMLBase64(n.textContent())
			if err != nil {
				certErr = fmt.Errorf("saml: malformed ds:X509Certificate in metadata: %w", err)
				return
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				certErr = fmt.Errorf("saml: parsing metadata certificate: %w", err)
				return
			}
			certs = append(certs, cert)
		})
		if certErr != nil {
			return nil, nil, certErr
		}
		if use == "" || use == "signing" {
			signing = append(signing, certs...)
		}
		if use == "" || use == "encryption" {
			encryption = append(encryption, certs...)
		}
	}
	return signing, encryption, nil
}

// endpoints collects the md endpoints of the given local name.
func endpoints(role *xnode, local string) ([]Endpoint, error) {
	var out []Endpoint
	for _, e := range role.childElements(nsMetadata, local) {
		ep := Endpoint{Index: -1}
		ep.Binding, _ = e.attrValue("", "Binding")
		ep.Location, _ = e.attrValue("", "Location")
		ep.ResponseLocation, _ = e.attrValue("", "ResponseLocation")
		if ep.Binding == "" || ep.Location == "" {
			return nil, fmt.Errorf("saml: md:%s is missing Binding or Location", local)
		}
		if v, ok := e.attrValue("", "index"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("saml: md:%s has a malformed index %q", local, v)
			}
			ep.Index = n
		}
		if v, ok := e.attrValue("", "isDefault"); ok {
			ep.IsDefault = v == "true" || v == "1"
		}
		out = append(out, ep)
	}
	return out, nil
}

// SSOURL returns the SingleSignOnService Location for the given binding, or ""
// when the IdP does not publish one.
func (m *IdPMetadata) SSOURL(binding string) string {
	return endpointLocation(m.SingleSignOnServices, binding, false)
}

// SLOURL returns the SingleLogoutService Location for the given binding, or ""
// when the IdP does not publish one.
func (m *IdPMetadata) SLOURL(binding string) string {
	return endpointLocation(m.SingleLogoutServices, binding, false)
}

// SLOResponseURL returns the SingleLogoutService ResponseLocation for the given
// binding, falling back to its Location. A LogoutResponse must be sent here,
// not to Location, when the two differ.
func (m *IdPMetadata) SLOResponseURL(binding string) string {
	return endpointLocation(m.SingleLogoutServices, binding, true)
}

// ArtifactResolutionURL returns the Location of the md:ArtifactResolutionService
// with the given index, or "" when the IdP publishes none with that index. A
// negative index selects the endpoint marked isDefault, falling back to the
// first one published.
//
// The index is a *configuration* choice. Do not pass the EndpointIndex out of a
// received artifact: that is a peer-controlled field, and letting it steer which
// URL is called is how the back channel becomes a server-side request forgery
// primitive.
func (m *IdPMetadata) ArtifactResolutionURL(index int) string {
	var first *Endpoint
	for i := range m.ArtifactResolutionServices {
		e := &m.ArtifactResolutionServices[i]
		if e.Binding != BindingSOAP {
			continue
		}
		if index >= 0 {
			if e.Index == index {
				return e.Location
			}
			continue
		}
		if e.IsDefault {
			return e.Location
		}
		if first == nil {
			first = e
		}
	}
	if index < 0 && first != nil {
		return first.Location
	}
	return ""
}

// ApplyToArtifactOptions sets the IdP-derived fields of an ArtifactOptions: the
// IdP entity ID, its signing certificates and the artifact resolution endpoint.
//
// index selects the md:ArtifactResolutionService to use; pass -1 for the default
// one. Using metadata is the recommended way to configure the endpoint, and is
// the only alternative to naming it directly — it is never taken from an
// artifact.
func (m *IdPMetadata) ApplyToArtifactOptions(o *ArtifactOptions, index int) error {
	if o == nil {
		return errors.New("saml: nil ArtifactOptions")
	}
	url := m.ArtifactResolutionURL(index)
	if url == "" {
		return fmt.Errorf("saml: IdP metadata has no md:ArtifactResolutionService with index %d", index)
	}
	o.IdPEntityID = m.EntityID
	o.IdPCertificates = append(o.IdPCertificates, m.SigningCertificates...)
	o.ArtifactResolutionURL = url
	return nil
}

func endpointLocation(eps []Endpoint, binding string, response bool) string {
	for _, e := range eps {
		if e.Binding != binding {
			continue
		}
		if response && e.ResponseLocation != "" {
			return e.ResponseLocation
		}
		return e.Location
	}
	return ""
}

// ApplyTo populates the IdP-derived fields of an ACS Options: the signing
// certificates. Everything else in Options describes this service provider and
// cannot come from the IdP's metadata.
func (m *IdPMetadata) ApplyTo(o *Options) {
	if o == nil {
		return
	}
	o.IdPCertificates = append(o.IdPCertificates, m.SigningCertificates...)
}

// ApplyToRequestOptions sets the AuthnRequest destination from the metadata,
// choosing the SingleSignOnService endpoint for the given binding — the binding
// used to *deliver the request*, so BindingHTTPRedirect for RedirectURL and
// BindingHTTPPost for PostBinding.
func (m *IdPMetadata) ApplyToRequestOptions(o *RequestOptions, binding string) error {
	if o == nil {
		return errors.New("saml: nil RequestOptions")
	}
	url := m.SSOURL(binding)
	if url == "" {
		return fmt.Errorf("%w for binding %q", ErrNoSSOService, binding)
	}
	o.SSOServiceURL = url
	return nil
}

// ApplyToSLOOptions sets the IdP-derived fields of an SLOOptions: the expected
// issuer, the signing certificates and the SLO endpoint for the given binding.
func (m *IdPMetadata) ApplyToSLOOptions(o *SLOOptions, binding string) error {
	if o == nil {
		return errors.New("saml: nil SLOOptions")
	}
	url := m.SLOURL(binding)
	if url == "" {
		return fmt.Errorf("saml: IdP metadata has no md:SingleLogoutService for binding %q", binding)
	}
	o.IdPEntityID = m.EntityID
	o.IdPCertificates = append(o.IdPCertificates, m.SigningCertificates...)
	o.IdPSingleLogoutServiceURL = url
	return nil
}

// --- SP metadata generation ------------------------------------------------

// SPMetadataOptions describes the service provider metadata document to
// generate for an identity provider to consume.
type SPMetadataOptions struct {
	// EntityID is this SP's entity ID. Required, and must equal
	// Options.Audience.
	EntityID string
	// ID is the document's ID attribute. Generated randomly when empty.
	ID string
	// AssertionConsumerServiceURL is the ACS endpoint. Required.
	AssertionConsumerServiceURL string
	// AssertionConsumerServiceBinding defaults to BindingHTTPPost.
	AssertionConsumerServiceBinding string
	// SingleLogoutServiceURL, when set, publishes an SLO endpoint.
	SingleLogoutServiceURL string
	// SingleLogoutServiceBinding defaults to BindingHTTPRedirect.
	SingleLogoutServiceBinding string
	// NameIDFormats are the formats this SP accepts.
	NameIDFormats []string
	// SigningCertificate, when set, is published as a signing KeyDescriptor
	// so the IdP can verify this SP's AuthnRequests and logout messages.
	SigningCertificate *x509.Certificate
	// AuthnRequestsSigned declares that this SP signs its AuthnRequests.
	AuthnRequestsSigned bool
	// WantAssertionsSigned declares that this SP requires signed assertions.
	// This package always does, so set it: leaving it false publishes a
	// claim about this SP that is not true.
	WantAssertionsSigned bool
	// ValidUntil, when non-zero, sets the validUntil attribute.
	ValidUntil time.Time
}

// GenerateSPMetadata renders an md:EntityDescriptor describing this service
// provider. The document is unsigned; publish it over HTTPS.
func GenerateSPMetadata(opts SPMetadataOptions) ([]byte, error) {
	if opts.EntityID == "" {
		return nil, errors.New("saml: SPMetadataOptions.EntityID is required")
	}
	if opts.AssertionConsumerServiceURL == "" {
		return nil, errors.New("saml: SPMetadataOptions.AssertionConsumerServiceURL is required")
	}
	if opts.AssertionConsumerServiceBinding == "" {
		opts.AssertionConsumerServiceBinding = BindingHTTPPost
	}
	if opts.SingleLogoutServiceBinding == "" {
		opts.SingleLogoutServiceBinding = BindingHTTPRedirect
	}
	id := opts.ID
	if id == "" {
		var err error
		if id, err = NewMessageID(); err != nil {
			return nil, err
		}
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<md:EntityDescriptor xmlns:md="` + nsMetadata + `"`)
	sb.WriteString(` xmlns:ds="` + nsDSig + `"`)
	sb.WriteString(` ID="` + escapeAttr(id) + `"`)
	sb.WriteString(` entityID="` + escapeAttr(opts.EntityID) + `"`)
	if !opts.ValidUntil.IsZero() {
		sb.WriteString(` validUntil="` + opts.ValidUntil.UTC().Format(time.RFC3339) + `"`)
	}
	sb.WriteString(`>`)
	sb.WriteString(`<md:SPSSODescriptor protocolSupportEnumeration="` + nsSAMLProtocol + `"`)
	sb.WriteString(` AuthnRequestsSigned="` + strconv.FormatBool(opts.AuthnRequestsSigned) + `"`)
	sb.WriteString(` WantAssertionsSigned="` + strconv.FormatBool(opts.WantAssertionsSigned) + `">`)
	if opts.SigningCertificate != nil {
		sb.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)
		sb.WriteString(base64.StdEncoding.EncodeToString(opts.SigningCertificate.Raw))
		sb.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	if opts.SingleLogoutServiceURL != "" {
		sb.WriteString(`<md:SingleLogoutService Binding="` + escapeAttr(opts.SingleLogoutServiceBinding) + `"`)
		sb.WriteString(` Location="` + escapeAttr(opts.SingleLogoutServiceURL) + `"/>`)
	}
	for _, f := range opts.NameIDFormats {
		sb.WriteString(`<md:NameIDFormat>` + escapeText(f) + `</md:NameIDFormat>`)
	}
	sb.WriteString(`<md:AssertionConsumerService Binding="` + escapeAttr(opts.AssertionConsumerServiceBinding) + `"`)
	sb.WriteString(` Location="` + escapeAttr(opts.AssertionConsumerServiceURL) + `" index="0" isDefault="true"/>`)
	sb.WriteString(`</md:SPSSODescriptor>`)
	sb.WriteString(`</md:EntityDescriptor>`)
	return []byte(sb.String()), nil
}

// --- xs:duration -----------------------------------------------------------

// Mean Gregorian intervals, in seconds, used by
// XSDuration.ApproximateDuration.
//
//   - A Gregorian year averages 365.2425 days — 365 days plus a leap day in
//     97 years out of every 400 — which is exactly 31556952 seconds.
//   - A month is that year divided by twelve: 30.436875 days, exactly 2629746
//     seconds.
//
// Both divide out exactly, so the approximation introduces no rounding of its
// own; what it does discard is the calendar, which is the whole reason the
// method is named "approximate".
const (
	secondsPerGregorianYear  = 31556952
	secondsPerGregorianMonth = 2629746
	secondsPerDay            = 86400
)

// ErrMalformedDuration is returned by ParseXSDuration for input that is not a
// valid xs:duration.
var ErrMalformedDuration = errors.New("saml: malformed xs:duration")

// XSDuration is a parsed xs:duration, the type SAML metadata uses for
// cacheDuration.
//
// The year and month components are kept apart from the fixed-length part on
// purpose. "P1M" is one calendar month — 28, 29, 30 or 31 days depending on
// where you start — and cannot be expressed as a time.Duration without choosing
// a starting instant. AddTo makes that choice explicit and correct;
// ApproximateDuration makes it explicit and approximate. There is no method that
// makes it silently.
//
// The zero value means "no duration", which for a metadata attribute means the
// attribute was absent. Present reports the difference.
type XSDuration struct {
	// Raw is the lexical form exactly as it was parsed, so a document can be
	// round-tripped without the parse having to be reversible.
	Raw string
	// Negative reports a leading "-": the whole duration runs backwards.
	Negative bool
	// Years, Months and Days are the calendar components, always
	// non-negative; the sign lives in Negative.
	Years, Months, Days int
	// Fixed is the hour, minute and second components combined. These are
	// fixed-length units, so they collapse into a time.Duration losslessly
	// (down to the nanosecond that time.Duration itself resolves).
	Fixed time.Duration
}

// Present reports whether the value came from an actual xs:duration rather than
// being a zero value standing in for an absent attribute.
func (d XSDuration) Present() bool { return d.Raw != "" }

// IsZero reports whether the duration is zero-length, i.e. "P0D" and its
// equivalents. An absent duration is also zero-length.
func (d XSDuration) IsZero() bool {
	return d.Years == 0 && d.Months == 0 && d.Days == 0 && d.Fixed == 0
}

// String returns the lexical form the value was parsed from, or the canonical
// rendering of a value constructed by hand.
func (d XSDuration) String() string {
	if d.Raw != "" {
		return d.Raw
	}
	var sb strings.Builder
	if d.Negative {
		sb.WriteByte('-')
	}
	sb.WriteByte('P')
	if d.Years != 0 {
		sb.WriteString(strconv.Itoa(d.Years) + "Y")
	}
	if d.Months != 0 {
		sb.WriteString(strconv.Itoa(d.Months) + "M")
	}
	if d.Days != 0 {
		sb.WriteString(strconv.Itoa(d.Days) + "D")
	}
	if d.Fixed != 0 {
		sb.WriteByte('T')
		rest := d.Fixed
		if h := rest / time.Hour; h != 0 {
			sb.WriteString(strconv.FormatInt(int64(h), 10) + "H")
			rest -= h * time.Hour
		}
		if m := rest / time.Minute; m != 0 {
			sb.WriteString(strconv.FormatInt(int64(m), 10) + "M")
			rest -= m * time.Minute
		}
		if rest != 0 {
			s := strings.TrimRight(strings.TrimRight(
				strconv.FormatFloat(rest.Seconds(), 'f', 9, 64), "0"), ".")
			sb.WriteString(s + "S")
		}
	}
	if sb.Len() == 1 || (d.Negative && sb.Len() == 2) {
		// xs:duration has no lexical form for "nothing at all".
		sb.WriteString("0D")
	}
	return sb.String()
}

// AddTo applies the duration to t and returns the result.
//
// The calendar components go through time.Time.AddDate, so the result respects
// month lengths and leap years — 2024-01-31 plus P1M is 2024-03-02, exactly as
// AddDate normalizes it — and the fixed part is added afterwards, so a duration
// spanning a daylight-saving transition shifts the wall clock for the calendar
// part and the elapsed time for the fixed part. Applying the two in the other
// order gives different, and wrong, answers.
func (d XSDuration) AddTo(t time.Time) time.Time {
	y, m, day := d.Years, d.Months, d.Days
	fixed := d.Fixed
	if d.Negative {
		y, m, day, fixed = -y, -m, -day, -fixed
	}
	return t.AddDate(y, m, day).Add(fixed)
}

// ApproximateDuration converts the whole duration to a time.Duration by valuing
// a year at 365.2425 days and a month at a twelfth of that, 30.436875 days.
//
// The name is a warning, not modesty. The result is wrong for any specific
// interval — P1M is 28 to 31 days, never 30.436875 — and is only fit for
// coarse-grained uses such as picking a cache refresh interval or comparing two
// durations. Use AddTo whenever the answer has to land on a real date.
func (d XSDuration) ApproximateDuration() time.Duration {
	secs := int64(d.Years)*secondsPerGregorianYear +
		int64(d.Months)*secondsPerGregorianMonth +
		int64(d.Days)*secondsPerDay
	out := time.Duration(secs)*time.Second + d.Fixed
	if d.Negative {
		return -out
	}
	return out
}

// ParseXSDuration parses an xs:duration: an optional "-", then "P", then any
// non-empty selection of nY, nM, nD, and after a "T" any non-empty selection of
// nH, nM, nS, in that order, with a fraction permitted only on the seconds.
//
// Note that the "M" designator means months before the "T" and minutes after it:
// P1M and PT1M are a month and a minute respectively, and confusing the two is
// the classic bug this type exists to prevent.
//
// Malformed input is an error, never a zero value. In particular a bare "P", a
// trailing "T" with no time components, an out-of-order or repeated designator,
// and a fraction anywhere but on the seconds are all rejected.
func ParseXSDuration(s string) (XSDuration, error) {
	d := XSDuration{Raw: s}
	t := strings.TrimSpace(s)
	if t == "" {
		return XSDuration{}, fmt.Errorf("%w: empty", ErrMalformedDuration)
	}
	if t[0] == '-' {
		d.Negative = true
		t = t[1:]
	}
	if t == "" || t[0] != 'P' {
		return XSDuration{}, fmt.Errorf("%w %q: missing the 'P' designator", ErrMalformedDuration, s)
	}
	t = t[1:]

	datePart, timePart, hasT := strings.Cut(t, "T")
	if datePart == "" && !hasT {
		return XSDuration{}, fmt.Errorf("%w %q: a duration needs at least one component", ErrMalformedDuration, s)
	}
	if hasT && timePart == "" {
		return XSDuration{}, fmt.Errorf("%w %q: 'T' is not followed by any time component", ErrMalformedDuration, s)
	}

	date, err := scanDurationFields(s, datePart, "YMD")
	if err != nil {
		return XSDuration{}, err
	}
	tm, err := scanDurationFields(s, timePart, "HMS")
	if err != nil {
		return XSDuration{}, err
	}
	if datePart != "" && date == ([3]string{}) {
		return XSDuration{}, fmt.Errorf("%w %q: no date component", ErrMalformedDuration, s)
	}
	if hasT && tm == ([3]string{}) {
		return XSDuration{}, fmt.Errorf("%w %q: no time component", ErrMalformedDuration, s)
	}

	if d.Years, err = durationInt(s, date[0], "years"); err != nil {
		return XSDuration{}, err
	}
	if d.Months, err = durationInt(s, date[1], "months"); err != nil {
		return XSDuration{}, err
	}
	if d.Days, err = durationInt(s, date[2], "days"); err != nil {
		return XSDuration{}, err
	}
	hours, err := durationInt(s, tm[0], "hours")
	if err != nil {
		return XSDuration{}, err
	}
	minutes, err := durationInt(s, tm[1], "minutes")
	if err != nil {
		return XSDuration{}, err
	}
	seconds, err := durationSeconds(s, tm[2])
	if err != nil {
		return XSDuration{}, err
	}
	// Guard the nanosecond conversion: time.Duration tops out at about 292
	// years, and an xs:duration is free to name more than that.
	total := int64(hours)*3600 + int64(minutes)*60
	if total > int64(1<<62)/int64(time.Second) {
		return XSDuration{}, fmt.Errorf("%w %q: fixed part is too large for a time.Duration", ErrMalformedDuration, s)
	}
	fixed := time.Duration(total) * time.Second
	if seconds > time.Duration(1<<62)-fixed {
		return XSDuration{}, fmt.Errorf("%w %q: fixed part is too large for a time.Duration", ErrMalformedDuration, s)
	}
	d.Fixed = fixed + seconds
	return d, nil
}

// scanDurationFields splits one half of a duration into its components,
// enforcing that designators appear in the order given and at most once each.
func scanDurationFields(whole, part, designators string) ([3]string, error) {
	var out [3]string
	next := 0
	for pos := 0; pos < len(part); {
		start := pos
		for pos < len(part) && (part[pos] >= '0' && part[pos] <= '9' || part[pos] == '.') {
			pos++
		}
		if pos == start {
			return out, fmt.Errorf("%w %q: expected a number before %q", ErrMalformedDuration, whole, part[pos:pos+1])
		}
		if pos >= len(part) {
			return out, fmt.Errorf("%w %q: value %q has no designator", ErrMalformedDuration, whole, part[start:])
		}
		i := strings.IndexByte(designators, part[pos])
		if i < 0 {
			return out, fmt.Errorf("%w %q: unexpected designator %q", ErrMalformedDuration, whole, part[pos:pos+1])
		}
		if i < next {
			return out, fmt.Errorf("%w %q: designator %q is out of order or repeated",
				ErrMalformedDuration, whole, part[pos:pos+1])
		}
		out[i] = part[start:pos]
		next = i + 1
		pos++
	}
	return out, nil
}

// durationInt parses a non-negative integer component, refusing the fraction
// that xs:duration allows only on the seconds.
func durationInt(whole, v, what string) (int, error) {
	if v == "" {
		return 0, nil
	}
	if strings.Contains(v, ".") {
		return 0, fmt.Errorf("%w %q: only the seconds component may be fractional", ErrMalformedDuration, whole)
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w %q: %s component %q is out of range", ErrMalformedDuration, whole, what, v)
	}
	return int(n), nil
}

// durationSeconds parses the seconds component, which may carry a fraction. It
// is converted to a time.Duration by decimal arithmetic rather than through a
// float64, so a value like 0.1S is exact rather than 99999999ns.
func durationSeconds(whole, v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	intPart, frac, hasDot := strings.Cut(v, ".")
	if hasDot && strings.Contains(frac, ".") {
		return 0, fmt.Errorf("%w %q: seconds value %q has more than one decimal point", ErrMalformedDuration, whole, v)
	}
	if intPart == "" && frac == "" {
		return 0, fmt.Errorf("%w %q: seconds value %q has no digits", ErrMalformedDuration, whole, v)
	}
	var secs int64
	if intPart != "" {
		n, err := strconv.ParseInt(intPart, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%w %q: seconds component %q is out of range", ErrMalformedDuration, whole, v)
		}
		secs = n
	}
	// Nanosecond resolution; anything finer is below what a time.Duration can
	// hold and is truncated rather than rounded.
	nanos := int64(0)
	if frac != "" {
		digits := frac
		if len(digits) > 9 {
			digits = digits[:9]
		}
		n, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w %q: seconds fraction %q is not numeric", ErrMalformedDuration, whole, frac)
		}
		for i := len(digits); i < 9; i++ {
			n *= 10
		}
		nanos = n
	}
	return time.Duration(secs)*time.Second + time.Duration(nanos), nil
}
