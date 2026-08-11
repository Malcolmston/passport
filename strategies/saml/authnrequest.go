package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// This file is the request half of the Web Browser SSO profile: building the
// samlp:AuthnRequest that starts SP-initiated single sign-on, and the two
// bindings that carry it to the identity provider. saml.go is the ACS half.
//
// Everything here is deliberately kept out of Options: producing a request is a
// separate concern from consuming a response, and the two need different
// credentials (the SP's own signing key versus the IdP's certificates).

// SAML 2.0 binding identifiers.
const (
	// BindingHTTPRedirect is the HTTP-Redirect binding: the message is
	// DEFLATE-compressed, base64-encoded and carried in the query string,
	// with any signature computed over the query string itself.
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	// BindingHTTPPost is the HTTP-POST binding: the message is base64-encoded
	// and carried in a form field, with any signature enveloped in the XML.
	BindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	// BindingHTTPArtifact is the HTTP-Artifact binding: the browser carries an
	// opaque SAMLart reference and the service provider fetches the message
	// itself over the back channel. See ArtifactResolver.
	BindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	// BindingSOAP is the SOAP binding used for that back channel, carrying a
	// samlp:ArtifactResolve and its samlp:ArtifactResponse.
	BindingSOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// Common saml:NameID Format identifiers, for RequestOptions.NameIDFormat.
const (
	NameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatEntity       = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// RequestedAuthnContext Comparison values.
const (
	ComparisonExact   = "exact"
	ComparisonMinimum = "minimum"
	ComparisonMaximum = "maximum"
	ComparisonBetter  = "better"
)

// SigAlg URIs, provided so callers can name one without typing the URL.
const (
	SigAlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SigAlgRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SigAlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SigAlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SigAlgECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SigAlgECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// Errors reported when building or verifying protocol messages.
var (
	// ErrNoSigningKey is returned when a binding that must be signed was
	// asked for but no signing key is configured.
	ErrNoSigningKey = errors.New("saml: no signing key configured")
	// ErrMissingSignature is returned when a received redirect-binding
	// message carries no Signature parameter and one is required.
	ErrMissingSignature = errors.New("saml: message is not signed")
	// ErrDuplicateParameter is returned when a redirect-binding query string
	// repeats a SAML parameter. A repeated parameter lets an attacker have
	// the verifier and the consumer read different values.
	ErrDuplicateParameter = errors.New("saml: duplicate SAML query parameter")
)

// digestURIForHash maps a hash back onto its xmldsig DigestMethod URI. It is
// the inverse of digestAlgorithms in xmldsig.go and is used when *producing*
// signatures; SHA-1 is absent because this package never generates it.
var digestURIForHash = map[crypto.Hash]string{
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

// signatureMarker is the placeholder a freshly built message carries where its
// enveloped ds:Signature belongs. It is an XML comment, so canonicalization
// discards it and a message digested with the marker still in place yields the
// same bytes as one with the marker removed.
const signatureMarker = "<!--SIGNATURE-->"

// RequestOptions configures the construction of AuthnRequests. It is separate
// from Options on purpose: the ACS strategy validates what the IdP sends, while
// this builds what the SP sends, and the two hold different keys.
type RequestOptions struct {
	// EntityID is this service provider's entity ID. It becomes the
	// request's saml:Issuer. Required.
	EntityID string

	// SSOServiceURL is the identity provider's SingleSignOnService endpoint.
	// It becomes the request's Destination and the URL a redirect points at.
	// Required.
	SSOServiceURL string

	// AssertionConsumerServiceURL is the SP endpoint the IdP should post the
	// response back to. Optional but strongly recommended: without it the IdP
	// falls back to whatever it has on file for this SP.
	AssertionConsumerServiceURL string

	// ProtocolBinding is the binding the IdP should use to return the
	// response. Defaults to BindingHTTPPost. Note this describes the
	// *response*; the binding used to deliver the request is chosen by
	// calling RedirectURL or PostBinding.
	ProtocolBinding string

	// NameIDFormat, when set, emits a samlp:NameIDPolicy requesting that
	// format.
	NameIDFormat string

	// AllowCreate sets the NameIDPolicy AllowCreate attribute. It is only
	// emitted when NameIDFormat is set.
	AllowCreate bool

	// ForceAuthn asks the IdP to re-authenticate the user even if it already
	// has a session.
	ForceAuthn bool

	// IsPassive asks the IdP not to take control of the user interface. The
	// IdP answers with a NoPassive status rather than prompting.
	IsPassive bool

	// AuthnContextClassRefs, when non-empty, emits a
	// samlp:RequestedAuthnContext naming these classes.
	AuthnContextClassRefs []string

	// Comparison is the RequestedAuthnContext Comparison attribute. Defaults
	// to "exact" when AuthnContextClassRefs is set.
	Comparison string

	// ProviderName is a human-readable name for this SP, shown by some IdPs.
	ProviderName string

	// SigningKey is the SP's private key. Without it, RedirectURL produces an
	// unsigned request and PostBinding refuses to sign. Many IdPs require
	// signed AuthnRequests; those that do not still benefit, since a signature
	// stops a third party from forging requests in this SP's name.
	SigningKey crypto.Signer

	// SigningCertificate, when set, is embedded as ds:X509Certificate in the
	// POST binding's KeyInfo so the IdP can select the right key.
	SigningCertificate *x509.Certificate

	// SignatureAlgorithm is the xmldsig SignatureMethod URI to sign with.
	// Defaults to RSA-SHA256 or ECDSA-SHA256 according to the key type.
	// SHA-1 algorithms are refused when signing, unconditionally.
	SignatureAlgorithm string

	// Clock supplies the current time; nil means time.Now.
	Clock func() time.Time

	// NewID generates request IDs. Nil means crypto/rand. Override it only in
	// tests: a predictable request ID lets an attacker fabricate an
	// InResponseTo and inject a response.
	NewID func() (string, error)

	// MaxDepth caps XML nesting while re-parsing messages this package built
	// in order to sign them. Defaults to 100.
	MaxDepth int
}

// RequestBuilder produces AuthnRequests. It is safe for concurrent use.
type RequestBuilder struct {
	opts   RequestOptions
	sigAlg string
}

// NewRequestBuilder validates opts and returns a builder.
//
// Unlike New, this reports configuration errors eagerly: there is no upstream
// API shape to preserve here, and a request builder that cannot build is worth
// finding out about at start-up.
func NewRequestBuilder(opts RequestOptions) (*RequestBuilder, error) {
	if opts.EntityID == "" {
		return nil, errors.New("saml: RequestOptions.EntityID is required")
	}
	if opts.SSOServiceURL == "" {
		return nil, errors.New("saml: RequestOptions.SSOServiceURL is required")
	}
	if opts.ProtocolBinding == "" {
		opts.ProtocolBinding = BindingHTTPPost
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.Comparison == "" {
		opts.Comparison = ComparisonExact
	}
	b := &RequestBuilder{opts: opts}
	var err error
	if b.sigAlg, err = resolveSigAlg(opts.SignatureAlgorithm, opts.SigningKey); err != nil {
		return nil, err
	}
	return b, nil
}

// resolveSigAlg picks the SignatureMethod URI to sign with, defaulting from the
// key type. An explicitly requested SHA-1 algorithm is refused: AllowSHA1
// exists so that a legacy IdP's signatures can still be *verified*, never so
// that this package produces one.
func resolveSigAlg(uri string, key crypto.Signer) (string, error) {
	if uri == "" {
		if key == nil {
			return SigAlgRSASHA256, nil
		}
		switch key.Public().(type) {
		case *rsa.PublicKey:
			return SigAlgRSASHA256, nil
		case *ecdsa.PublicKey:
			return SigAlgECDSASHA256, nil
		default:
			return "", fmt.Errorf("saml: unsupported signing key type %T", key.Public())
		}
	}
	alg, ok := signatureAlgorithms[uri]
	if !ok {
		return "", fmt.Errorf("saml: unsupported signature algorithm %q", uri)
	}
	if alg.weak {
		return "", fmt.Errorf("%w: %s may not be used for signing", ErrWeakAlgorithm, uri)
	}
	if _, ok := digestURIForHash[alg.hash]; !ok {
		return "", fmt.Errorf("saml: no digest URI for %q", uri)
	}
	return uri, nil
}

func (b *RequestBuilder) now() time.Time {
	if b.opts.Clock != nil {
		return b.opts.Clock()
	}
	return time.Now()
}

func (b *RequestBuilder) newID() (string, error) {
	if b.opts.NewID != nil {
		return b.opts.NewID()
	}
	return NewMessageID()
}

// NewMessageID returns a fresh SAML message ID: an "_" followed by 32 hex
// characters of crypto/rand output.
//
// The leading underscore is required — an xs:ID may not start with a digit —
// and the randomness is required for security, not just uniqueness. The
// AuthnRequest ID comes back in the response's InResponseTo, so a predictable
// ID lets an attacker construct a response that appears to answer a request the
// user never made. Never derive a message ID from a counter or a timestamp.
func NewMessageID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("saml: generating message ID: %w", err)
	}
	return "_" + hex.EncodeToString(b[:]), nil
}

// AuthnRequest is a built samlp:AuthnRequest.
//
// Persist ID before redirecting the user and check it against the response's
// InResponseTo, via Options.ValidateInResponseTo, when the response comes back.
// Without that check a response from an unrelated login can be replayed into
// this session.
type AuthnRequest struct {
	// ID is the request's ID attribute.
	ID string
	// IssueInstant is the request's IssueInstant.
	IssueInstant time.Time
	// Destination is the IdP endpoint the request is addressed to.
	Destination string
	// XML is the unsigned request document. RedirectURL uses it as-is; the
	// POST binding signs a copy.
	XML []byte

	// tmpl is XML with signatureMarker still in place, so an enveloped
	// signature can be inserted at the schema-mandated position.
	tmpl string
}

// BuildAuthnRequest constructs a new AuthnRequest with a fresh random ID.
func (b *RequestBuilder) BuildAuthnRequest() (*AuthnRequest, error) {
	id, err := b.newID()
	if err != nil {
		return nil, err
	}
	now := b.now().UTC()
	o := &b.opts

	var sb strings.Builder
	sb.WriteString(`<samlp:AuthnRequest xmlns:samlp="` + nsSAMLProtocol + `"`)
	sb.WriteString(` xmlns:saml="` + nsSAMLAssertion + `"`)
	sb.WriteString(` ID="` + escapeAttr(id) + `"`)
	sb.WriteString(` Version="2.0"`)
	sb.WriteString(` IssueInstant="` + now.Format(time.RFC3339) + `"`)
	sb.WriteString(` Destination="` + escapeAttr(o.SSOServiceURL) + `"`)
	if o.AssertionConsumerServiceURL != "" {
		sb.WriteString(` AssertionConsumerServiceURL="` + escapeAttr(o.AssertionConsumerServiceURL) + `"`)
		sb.WriteString(` ProtocolBinding="` + escapeAttr(o.ProtocolBinding) + `"`)
	}
	if o.ForceAuthn {
		sb.WriteString(` ForceAuthn="true"`)
	}
	if o.IsPassive {
		sb.WriteString(` IsPassive="true"`)
	}
	if o.ProviderName != "" {
		sb.WriteString(` ProviderName="` + escapeAttr(o.ProviderName) + `"`)
	}
	sb.WriteString(`>`)
	sb.WriteString(`<saml:Issuer>` + escapeText(o.EntityID) + `</saml:Issuer>`)
	// Schema order for samlp:AuthnRequest is Issuer, Signature, Extensions,
	// Subject, NameIDPolicy, Conditions, RequestedAuthnContext, Scoping.
	sb.WriteString(signatureMarker)
	if o.NameIDFormat != "" {
		sb.WriteString(`<samlp:NameIDPolicy Format="` + escapeAttr(o.NameIDFormat) + `"`)
		if o.AllowCreate {
			sb.WriteString(` AllowCreate="true"`)
		}
		sb.WriteString(`/>`)
	}
	if len(o.AuthnContextClassRefs) > 0 {
		sb.WriteString(`<samlp:RequestedAuthnContext Comparison="` + escapeAttr(o.Comparison) + `">`)
		for _, ref := range o.AuthnContextClassRefs {
			sb.WriteString(`<saml:AuthnContextClassRef>` + escapeText(ref) + `</saml:AuthnContextClassRef>`)
		}
		sb.WriteString(`</samlp:RequestedAuthnContext>`)
	}
	sb.WriteString(`</samlp:AuthnRequest>`)

	tmpl := sb.String()
	return &AuthnRequest{
		ID:           id,
		IssueInstant: now,
		Destination:  o.SSOServiceURL,
		XML:          []byte(strings.Replace(tmpl, signatureMarker, "", 1)),
		tmpl:         tmpl,
	}, nil
}

// RedirectURL renders req for the HTTP-Redirect binding and returns the
// absolute URL to send the browser to. relayState may be empty.
//
// When RequestOptions.SigningKey is set the URL carries a SigAlg and Signature
// computed over the query string exactly as the binding specification requires;
// see redirectSignedString for why the construction matters.
func (b *RequestBuilder) RedirectURL(req *AuthnRequest, relayState string) (string, error) {
	if req == nil {
		return "", errors.New("saml: nil AuthnRequest")
	}
	return redirectBindingURL(req.Destination, "SAMLRequest", req.XML, relayState, b.opts.SigningKey, b.sigAlg)
}

// PostBinding renders req for the HTTP-POST binding. When a signing key is
// configured the returned document carries an enveloped XML signature over the
// whole AuthnRequest; without one it refuses, because an unsigned POST-binding
// request is indistinguishable from a forged one.
func (b *RequestBuilder) PostBinding(req *AuthnRequest, relayState string) (*PostBinding, error) {
	if req == nil {
		return nil, errors.New("saml: nil AuthnRequest")
	}
	if b.opts.SigningKey == nil {
		return nil, ErrNoSigningKey
	}
	signed, err := signEnveloped(req.tmpl, req.ID, b.opts.SigningKey, b.opts.SigningCertificate, b.sigAlg, b.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	return &PostBinding{
		URL:        req.Destination,
		Field:      "SAMLRequest",
		Value:      base64.StdEncoding.EncodeToString(signed),
		RelayState: relayState,
	}, nil
}

// PostBinding is a message rendered for the HTTP-POST binding: the values a
// browser must submit, plus the endpoint to submit them to.
type PostBinding struct {
	// URL is the endpoint the form posts to.
	URL string
	// Field is "SAMLRequest" or "SAMLResponse".
	Field string
	// Value is the base64-encoded XML message.
	Value string
	// RelayState is echoed back by the peer; empty means omit it.
	RelayState string
}

// FormValues returns the POST body parameters.
func (p *PostBinding) FormValues() url.Values {
	v := url.Values{p.Field: {p.Value}}
	if p.RelayState != "" {
		v.Set("RelayState", p.RelayState)
	}
	return v
}

// HTMLForm renders a self-submitting HTML form, which is how the POST binding
// is delivered through a browser. Every value is HTML-escaped.
func (p *PostBinding) HTMLForm() string {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><title>SAML</title></head>`)
	sb.WriteString(`<body onload="document.forms[0].submit()">`)
	sb.WriteString(`<noscript><p>JavaScript is disabled; press the button to continue.</p></noscript>`)
	sb.WriteString(`<form method="post" action="` + html.EscapeString(p.URL) + `">`)
	sb.WriteString(`<input type="hidden" name="` + html.EscapeString(p.Field) + `" value="` + html.EscapeString(p.Value) + `"/>`)
	if p.RelayState != "" {
		sb.WriteString(`<input type="hidden" name="RelayState" value="` + html.EscapeString(p.RelayState) + `"/>`)
	}
	sb.WriteString(`<noscript><input type="submit" value="Continue"/></noscript>`)
	sb.WriteString(`</form></body></html>`)
	return sb.String()
}

// --- HTTP-Redirect binding ------------------------------------------------

// DeflateEncode DEFLATE-compresses and base64-encodes a SAML message for the
// HTTP-Redirect binding.
//
// The binding specifies the *raw* DEFLATE stream of RFC 1951, with no zlib
// (RFC 1950) header and no adler32 trailer, which is what compress/flate
// produces. Using compress/zlib here is the classic mistake and produces a
// message the IdP cannot inflate.
func DeflateEncode(msg []byte) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("saml: deflate: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return "", fmt.Errorf("saml: deflate: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("saml: deflate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DeflateDecode reverses DeflateEncode, refusing to inflate more than maxBytes.
// The cap is essential: a few hundred bytes of query string can inflate to
// gigabytes, so an unbounded inflate is a denial-of-service primitive.
func DeflateDecode(b64 string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	compressed, err := decodeBase64(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("saml: malformed base64 in redirect binding: %w", err)
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	// Read one byte past the cap so an over-long stream is detected rather
	// than silently truncated.
	out, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("saml: inflate: %w", err)
	}
	if len(out) > maxBytes {
		return nil, ErrTooLarge
	}
	return out, nil
}

// redirectSignedString builds the exact octet string the HTTP-Redirect binding
// signs, per SAML 2.0 Bindings section 3.4.4.1.
//
// The string is the concatenation of the URL-encoded parameters in this fixed
// order — SAMLRequest or SAMLResponse first, then RelayState if and only if it
// is present, then SigAlg — joined by "&", with no other parameters and no
// "Signature" parameter. Order is normative and is not the order they happen to
// appear in the query string.
//
// On the verifying side the values passed in here MUST be the percent-encoded
// octets as received. Re-encoding a decoded value is the classic exploitable
// bug: two different encodings of the same value ("%41" and "A", "+" and "%20")
// produce different signed strings, so a verifier that re-serializes will
// happily validate a signature over a string the peer never signed, or reject a
// legitimate one.
func redirectSignedString(field, encodedMsg string, hasRelayState bool, encodedRelayState, encodedSigAlg string) string {
	var sb strings.Builder
	sb.WriteString(field)
	sb.WriteByte('=')
	sb.WriteString(encodedMsg)
	if hasRelayState {
		sb.WriteString("&RelayState=")
		sb.WriteString(encodedRelayState)
	}
	sb.WriteString("&SigAlg=")
	sb.WriteString(encodedSigAlg)
	return sb.String()
}

// redirectBindingURL renders doc for the HTTP-Redirect binding and appends it
// to destination, signing the query string when key is non-nil.
func redirectBindingURL(destination, field string, doc []byte, relayState string, key crypto.Signer, sigAlgURI string) (string, error) {
	if destination == "" {
		return "", errors.New("saml: no destination URL for the redirect binding")
	}
	encoded, err := DeflateEncode(doc)
	if err != nil {
		return "", err
	}
	query := field + "=" + url.QueryEscape(encoded)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if key != nil {
		alg, ok := signatureAlgorithms[sigAlgURI]
		if !ok {
			return "", fmt.Errorf("saml: unsupported signature algorithm %q", sigAlgURI)
		}
		if alg.weak {
			return "", fmt.Errorf("%w: %s may not be used for signing", ErrWeakAlgorithm, sigAlgURI)
		}
		signed := redirectSignedString(field, url.QueryEscape(encoded), relayState != "", url.QueryEscape(relayState), url.QueryEscape(sigAlgURI))
		hashFn, err := newHash(alg.hash)
		if err != nil {
			return "", err
		}
		sig, err := signDigest(key, alg, hashFn([]byte(signed)))
		if err != nil {
			return "", err
		}
		query = signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}

	u, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("saml: malformed destination URL %q: %w", destination, err)
	}
	if u.RawQuery == "" {
		u.RawQuery = query
	} else {
		// An endpoint may legitimately carry its own query parameters. They
		// are not covered by the signature, which is why they must be kept
		// out of the signed string above.
		u.RawQuery += "&" + query
	}
	return u.String(), nil
}

// rawQueryParam returns the still-percent-encoded value of the named parameter
// in rawQuery, rejecting a repeated name.
func rawQueryParam(rawQuery, name string) (string, bool, error) {
	var (
		value string
		found bool
	)
	for _, seg := range strings.Split(rawQuery, "&") {
		if seg == "" {
			continue
		}
		k, v, _ := strings.Cut(seg, "=")
		if k != name {
			continue
		}
		if found {
			return "", false, fmt.Errorf("%w: %s", ErrDuplicateParameter, name)
		}
		value, found = v, true
	}
	return value, found, nil
}

// redirectMessage is a message received over the HTTP-Redirect binding.
type redirectMessage struct {
	xml        []byte
	relayState string
	signed     bool
}

// parseRedirect decodes and, when certificates are configured, verifies a
// message received over the HTTP-Redirect binding.
//
// rawQuery must be the request's raw, undecoded query string — r.URL.RawQuery,
// never r.URL.Query(). Values recovered from a parsed url.Values have already
// lost the exact encoding the peer signed over.
func parseRedirect(rawQuery, field string, certs []*x509.Certificate, allowSHA1 bool, requireSignature bool, maxBytes int) (*redirectMessage, error) {
	rawMsg, ok, err := rawQueryParam(rawQuery, field)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("saml: query string has no %s parameter", field)
	}
	rawRelay, hasRelay, err := rawQueryParam(rawQuery, "RelayState")
	if err != nil {
		return nil, err
	}
	rawSigAlg, hasSigAlg, err := rawQueryParam(rawQuery, "SigAlg")
	if err != nil {
		return nil, err
	}
	rawSig, hasSig, err := rawQueryParam(rawQuery, "Signature")
	if err != nil {
		return nil, err
	}

	msgB64, err := url.QueryUnescape(rawMsg)
	if err != nil {
		return nil, fmt.Errorf("saml: malformed %s parameter: %w", field, err)
	}
	relayState := ""
	if hasRelay {
		if relayState, err = url.QueryUnescape(rawRelay); err != nil {
			return nil, fmt.Errorf("saml: malformed RelayState parameter: %w", err)
		}
	}
	doc, err := DeflateDecode(msgB64, maxBytes)
	if err != nil {
		return nil, err
	}

	out := &redirectMessage{xml: doc, relayState: relayState}
	if !hasSig || !hasSigAlg {
		if requireSignature {
			return nil, ErrMissingSignature
		}
		return out, nil
	}
	if len(certs) == 0 {
		if requireSignature {
			return nil, ErrNoCertificates
		}
		return out, nil
	}

	sigAlgURI, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return nil, fmt.Errorf("saml: malformed SigAlg parameter: %w", err)
	}
	alg, ok := signatureAlgorithms[sigAlgURI]
	if !ok {
		return nil, fmt.Errorf("saml: unsupported signature algorithm %q", sigAlgURI)
	}
	if alg.weak && !allowSHA1 {
		return nil, fmt.Errorf("%w: %s", ErrWeakAlgorithm, sigAlgURI)
	}
	sigB64, err := url.QueryUnescape(rawSig)
	if err != nil {
		return nil, fmt.Errorf("saml: malformed Signature parameter: %w", err)
	}
	signature, err := decodeXMLBase64(sigB64)
	if err != nil {
		return nil, fmt.Errorf("saml: malformed Signature parameter: %w", err)
	}

	// The signed string is rebuilt from the received octets, never from the
	// decoded values. RelayState participates if and only if it was present.
	signedString := redirectSignedString(field, rawMsg, hasRelay, rawRelay, rawSigAlg)
	hashFn, err := newHash(alg.hash)
	if err != nil {
		return nil, err
	}
	digest := hashFn([]byte(signedString))
	for _, c := range certs {
		if verifyRaw(c.PublicKey, alg, digest, signature) == nil {
			out.signed = true
			return out, nil
		}
	}
	return nil, ErrSignatureInvalid
}

// --- enveloped XML signature generation -----------------------------------

// signEnveloped inserts an enveloped ds:Signature over the element refID names.
//
// tmpl must contain exactly one signatureMarker, positioned where the schema
// requires the ds:Signature to sit. The digest is taken over the document with
// the marker removed, which is precisely the node set the enveloped-signature
// transform yields, so the result verifies through the same verifySignature
// path the ACS side uses.
func signEnveloped(tmpl, refID string, key crypto.Signer, cert *x509.Certificate, sigAlgURI string, maxDepth int) ([]byte, error) {
	if key == nil {
		return nil, ErrNoSigningKey
	}
	if !strings.Contains(tmpl, signatureMarker) {
		return nil, errors.New("saml: message has no signature placeholder")
	}
	alg, ok := signatureAlgorithms[sigAlgURI]
	if !ok {
		return nil, fmt.Errorf("saml: unsupported signature algorithm %q", sigAlgURI)
	}
	if alg.weak {
		return nil, fmt.Errorf("%w: %s may not be used for signing", ErrWeakAlgorithm, sigAlgURI)
	}
	digestURI, ok := digestURIForHash[alg.hash]
	if !ok {
		return nil, fmt.Errorf("saml: no digest URI for %q", sigAlgURI)
	}
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	hashFn, err := newHash(alg.hash)
	if err != nil {
		return nil, err
	}

	// 1. Digest the message as the enveloped-signature transform leaves it.
	bare := strings.Replace(tmpl, signatureMarker, "", 1)
	root, err := parseXML([]byte(bare), maxDepth)
	if err != nil {
		return nil, fmt.Errorf("saml: re-parsing message to sign it: %w", err)
	}
	target, err := resolveIDRef(root, refID)
	if err != nil {
		return nil, err
	}
	canon, err := canonicalize(target, c14nOptions{exclusive: true})
	if err != nil {
		return nil, err
	}
	digest := base64.StdEncoding.EncodeToString(hashFn(canon))

	// 2. Splice in a ds:Signature with an empty SignatureValue.
	var sb strings.Builder
	sb.WriteString(`<ds:Signature xmlns:ds="` + nsDSig + `">`)
	sb.WriteString(`<ds:SignedInfo>`)
	sb.WriteString(`<ds:CanonicalizationMethod Algorithm="` + AlgC14NExclusive + `"/>`)
	sb.WriteString(`<ds:SignatureMethod Algorithm="` + sigAlgURI + `"/>`)
	sb.WriteString(`<ds:Reference URI="#` + escapeAttr(refID) + `">`)
	sb.WriteString(`<ds:Transforms>`)
	sb.WriteString(`<ds:Transform Algorithm="` + AlgEnvelopedSignature + `"/>`)
	sb.WriteString(`<ds:Transform Algorithm="` + AlgC14NExclusive + `"/>`)
	sb.WriteString(`</ds:Transforms>`)
	sb.WriteString(`<ds:DigestMethod Algorithm="` + digestURI + `"/>`)
	sb.WriteString(`<ds:DigestValue>` + digest + `</ds:DigestValue>`)
	sb.WriteString(`</ds:Reference>`)
	sb.WriteString(`</ds:SignedInfo>`)
	sb.WriteString(`<ds:SignatureValue></ds:SignatureValue>`)
	if cert != nil {
		sb.WriteString(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)
		sb.WriteString(base64.StdEncoding.EncodeToString(cert.Raw))
		sb.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)
	}
	sb.WriteString(`</ds:Signature>`)
	doc := strings.Replace(tmpl, signatureMarker, sb.String(), 1)

	// 3. Sign the canonical SignedInfo and fill the value in.
	root, err = parseXML([]byte(doc), maxDepth)
	if err != nil {
		return nil, fmt.Errorf("saml: re-parsing signed message: %w", err)
	}
	var signedInfo *xnode
	root.walk(func(n *xnode) {
		if signedInfo != nil || !n.is(nsDSig, "SignedInfo") {
			return
		}
		signedInfo = n
	})
	if signedInfo == nil {
		return nil, errors.New("saml: internal error: no ds:SignedInfo after splicing")
	}
	canonSI, err := canonicalize(signedInfo, c14nOptions{exclusive: true})
	if err != nil {
		return nil, err
	}
	value, err := signDigest(key, alg, hashFn(canonSI))
	if err != nil {
		return nil, err
	}
	return []byte(strings.Replace(doc,
		"<ds:SignatureValue></ds:SignatureValue>",
		"<ds:SignatureValue>"+base64.StdEncoding.EncodeToString(value)+"</ds:SignatureValue>", 1)), nil
}

// ecdsaASN1Signature mirrors the SEQUENCE crypto/ecdsa emits.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// signDigest produces a signature value in the encoding xmldsig expects. It is
// the counterpart of verifyRaw in xmldsig.go, and in particular converts the
// ASN.1 ECDSA signature crypto.Signer returns into the fixed-width r||s
// concatenation the XML Signature ECDSA profile mandates.
func signDigest(key crypto.Signer, alg sigAlgorithm, digest []byte) ([]byte, error) {
	switch alg.kind {
	case sigRSAPKCS1:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("saml: signature algorithm needs an RSA key, got %T", key.Public())
		}
		return key.Sign(rand.Reader, digest, alg.hash)
	case sigRSAPSS:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("saml: signature algorithm needs an RSA key, got %T", key.Public())
		}
		return key.Sign(rand.Reader, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       alg.hash,
		})
	case sigECDSA:
		pub, ok := key.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("saml: signature algorithm needs an ECDSA key, got %T", key.Public())
		}
		der, err := key.Sign(rand.Reader, digest, alg.hash)
		if err != nil {
			return nil, err
		}
		var parsed ecdsaASN1Signature
		if _, err := asn1.Unmarshal(der, &parsed); err != nil {
			return nil, fmt.Errorf("saml: decoding ECDSA signature: %w", err)
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		if parsed.R.BitLen() > size*8 || parsed.S.BitLen() > size*8 {
			return nil, errors.New("saml: ECDSA signature does not fit the curve")
		}
		parsed.R.FillBytes(out[:size])
		parsed.S.FillBytes(out[size:])
		return out, nil
	}
	return nil, errors.New("saml: unsupported signature kind")
}
