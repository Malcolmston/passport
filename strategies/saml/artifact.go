package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// This file implements the service-provider side of the SAML 2.0 HTTP-Artifact
// binding: the browser arrives at the assertion consumer service carrying only a
// short opaque reference (the SAMLart parameter), and the SP fetches the real
// samlp:Response over a SOAP back channel (soap.go) with a samlp:ArtifactResolve
// request.
//
// # Why the binding exists
//
// The POST binding hands the whole assertion to the browser. The artifact
// binding hands it a 44-byte token instead and moves the assertion onto a
// direct, mutually-authenticated channel between the two servers, so the
// assertion never passes through the user agent at all.
//
// # What has to be checked, and why
//
// An artifact is attacker-supplied: anybody can hit the ACS endpoint with a
// SAMLart of their choosing. Three properties make handling one safe.
//
//  1. The artifact's SourceID must be the SHA-1 of the *configured* identity
//     provider's entity ID. Without this check an attacker points the artifact at
//     an identity provider of their own choosing, and every later "the signature
//     verified" statement is about the wrong issuer.
//
//  2. The resolution endpoint is never read out of the artifact or out of any
//     other attacker-supplied field. It comes from ArtifactOptions or from
//     parsed IdP metadata. An endpoint the peer controls turns this code into a
//     server-side request forgery gadget aimed at whatever the SP can reach.
//
//  3. The artifact is single-use. It is consumed through the same ReplayCache
//     the assertion IDs go through, before the network call rather than after,
//     so that a replayed artifact cannot even generate back-channel traffic.
//
// Everything that comes back is then verified through the ordinary machinery:
// the samlp:ArtifactResponse's own signature, and the samlp:Response inside it,
// which is handed to Strategy.Validate for the full pipeline.

// ArtifactTypeCode0004 is the artifact type code defined by the SAML 2.0
// Bindings specification, section 3.6.4.2. It is the only type this package
// resolves; a type code an implementation does not understand cannot be safely
// guessed at.
const ArtifactTypeCode0004 = 0x0004

// ArtifactLength is the octet length of a decoded type 0x0004 artifact: a
// 2-octet TypeCode, a 2-octet EndpointIndex, a 20-octet SourceID and a 20-octet
// MessageHandle.
const ArtifactLength = 44

// DefaultArtifactTTL is how long a consumed artifact is remembered by the replay
// cache when ArtifactOptions.ArtifactTTL is not set.
const DefaultArtifactTTL = 5 * time.Minute

// Errors reported by artifact handling.
var (
	// ErrMalformedArtifact is returned when the SAMLart parameter is not
	// base64, is not ArtifactLength octets long, or carries a TypeCode other
	// than ArtifactTypeCode0004.
	ErrMalformedArtifact = errors.New("saml: malformed SAML artifact")
	// ErrArtifactSourceID is returned when the artifact's SourceID is not the
	// SHA-1 of the configured identity provider's entity ID. This is the check
	// that stops an artifact aiming the service provider at a different IdP.
	ErrArtifactSourceID = errors.New("saml: artifact SourceID does not identify the configured identity provider")
	// ErrArtifactStatus is returned when the samlp:ArtifactResponse carries a
	// StatusCode other than Success.
	ErrArtifactStatus = errors.New("saml: artifact response status is not Success")
	// ErrArtifactInResponseTo is returned when the ArtifactResponse answers a
	// request this service provider did not send.
	ErrArtifactInResponseTo = errors.New("saml: artifact response InResponseTo does not match the request")
)

// Artifact is a parsed SAML 2.0 type 0x0004 artifact.
type Artifact struct {
	// TypeCode is the artifact type; always ArtifactTypeCode0004 for a value
	// this package produced or accepted.
	TypeCode uint16
	// EndpointIndex is the index the identity provider assigned to the
	// artifact resolution endpoint it expects to be called back on.
	//
	// It is informational here and is NEVER used to choose a URL. The endpoint
	// comes from configuration or metadata; see the discussion at the top of
	// this file.
	EndpointIndex uint16
	// SourceID is the SHA-1 of the issuing identity provider's entity ID.
	SourceID [20]byte
	// MessageHandle is the identity provider's opaque, unguessable reference
	// to the message being held.
	MessageHandle [20]byte
	// Raw is the decoded 44-octet artifact.
	Raw []byte
}

// SourceIDFor returns the SourceID a type 0x0004 artifact carries for the given
// entity ID: the SHA-1 of its UTF-8 octets, per SAML 2.0 Bindings 3.6.4.2.
//
// SHA-1 is used here as a fixed-width identifier, not as a security primitive.
// Its collision weakness is irrelevant: the value is compared against a
// configured entity ID, and a matching SourceID grants nothing on its own — the
// ArtifactResponse still has to be signed by a configured certificate.
func SourceIDFor(entityID string) [20]byte {
	return sha1.Sum([]byte(entityID))
}

// ParseArtifact decodes a base64 SAMLart parameter.
//
// It rejects any type code other than ArtifactTypeCode0004 and any length other
// than ArtifactLength; it does not check the SourceID, which needs the
// configured identity provider. Use Artifact.CheckSourceID, or let
// ArtifactResolver.Resolve do it.
func ParseArtifact(samlArt string) (*Artifact, error) {
	raw, err := decodeBase64(strings.TrimSpace(samlArt))
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64: %v", ErrMalformedArtifact, err)
	}
	if len(raw) != ArtifactLength {
		return nil, fmt.Errorf("%w: %d octets, expected %d", ErrMalformedArtifact, len(raw), ArtifactLength)
	}
	a := &Artifact{
		TypeCode:      binary.BigEndian.Uint16(raw[0:2]),
		EndpointIndex: binary.BigEndian.Uint16(raw[2:4]),
		Raw:           append([]byte(nil), raw...),
	}
	if a.TypeCode != ArtifactTypeCode0004 {
		return nil, fmt.Errorf("%w: type code 0x%04x is not supported", ErrMalformedArtifact, a.TypeCode)
	}
	copy(a.SourceID[:], raw[4:24])
	copy(a.MessageHandle[:], raw[24:44])
	return a, nil
}

// NewArtifact builds a type 0x0004 artifact for entityID with a fresh
// crypto/rand MessageHandle.
//
// This is the identity-provider side of the binding, provided so that the
// service-provider side can be exercised end to end. The MessageHandle must be
// unguessable: anyone who can predict one can resolve an artifact the identity
// provider issued for somebody else, so it is generated from crypto/rand and
// never from a counter, a timestamp or a hash of the session.
func NewArtifact(entityID string, endpointIndex uint16) (*Artifact, error) {
	a := &Artifact{
		TypeCode:      ArtifactTypeCode0004,
		EndpointIndex: endpointIndex,
		SourceID:      SourceIDFor(entityID),
	}
	if _, err := rand.Read(a.MessageHandle[:]); err != nil {
		return nil, fmt.Errorf("saml: generating artifact message handle: %w", err)
	}
	raw := make([]byte, ArtifactLength)
	binary.BigEndian.PutUint16(raw[0:2], a.TypeCode)
	binary.BigEndian.PutUint16(raw[2:4], a.EndpointIndex)
	copy(raw[4:24], a.SourceID[:])
	copy(raw[24:44], a.MessageHandle[:])
	a.Raw = raw
	return a, nil
}

// String returns the base64 SAMLart parameter value.
func (a *Artifact) String() string {
	if a == nil || len(a.Raw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(a.Raw)
}

// CheckSourceID reports whether the artifact was issued by entityID, comparing
// in constant time.
func (a *Artifact) CheckSourceID(entityID string) error {
	want := SourceIDFor(entityID)
	if subtle.ConstantTimeCompare(a.SourceID[:], want[:]) != 1 {
		return fmt.Errorf("%w (expected the SourceID of %q)", ErrArtifactSourceID, entityID)
	}
	return nil
}

// ArtifactOptions configures artifact resolution. Like RequestOptions and
// SLOOptions it is separate from Options: resolving an artifact needs the SP's
// own signing key and a network endpoint, neither of which the assertion
// consumer has any business holding.
type ArtifactOptions struct {
	// EntityID is this service provider's entity ID. It becomes the
	// saml:Issuer of the ArtifactResolve. Required.
	EntityID string

	// IdPEntityID is the identity provider's entity ID. Required: it is what
	// the artifact's SourceID is checked against, and it is the only
	// saml:Issuer accepted on the ArtifactResponse.
	IdPEntityID string

	// ArtifactResolutionURL is the identity provider's
	// md:ArtifactResolutionService endpoint.
	//
	// It MUST come from configuration or from IdP metadata — see
	// IdPMetadata.ApplyToArtifactOptions — and never from the artifact, a
	// query parameter, or any other field the peer controls. Required.
	ArtifactResolutionURL string

	// IdPCertificates are the identity provider's signing certificates, used
	// to verify the ArtifactResponse and the samlp:Response inside it. Without
	// at least one, every resolution is rejected.
	IdPCertificates []*x509.Certificate

	// IdPCertificatePEM is an alternative to IdPCertificates accepting
	// concatenated PEM CERTIFICATE blocks. Both may be set; they are merged.
	IdPCertificatePEM []byte

	// SigningKey, when set, signs the outgoing ArtifactResolve. Identity
	// providers commonly require it, and it is what proves to the IdP that
	// this SP, rather than whoever intercepted the artifact, is redeeming it.
	SigningKey crypto.Signer

	// SigningCertificate is embedded as ds:X509Certificate in the outgoing
	// signature's KeyInfo so the IdP can select the right key.
	SigningCertificate *x509.Certificate

	// SignatureAlgorithm is the SignatureMethod URI to sign with. Defaults to
	// RSA-SHA256 or ECDSA-SHA256 according to the key type.
	SignatureAlgorithm string

	// AllowSHA1 permits SHA-1 signatures on the *incoming* ArtifactResponse.
	// Outgoing messages are never signed with SHA-1.
	AllowSHA1 bool

	// HTTPClient is the client used for the back channel. When nil a client
	// with DefaultSOAPTimeout is used. A supplied client is copied, not
	// mutated: a missing Timeout and a missing CheckRedirect are filled in on
	// the copy. A client whose *http.Transport sets InsecureSkipVerify is
	// rejected by NewArtifactResolver.
	HTTPClient *http.Client

	// Timeout overrides the back-channel timeout. Zero keeps the supplied
	// client's timeout, or DefaultSOAPTimeout when it has none. There is no
	// "no timeout" setting: an unbounded back-channel call is a
	// denial-of-service vector against this service provider.
	Timeout time.Duration

	// ReplayCache records consumed artifacts so that one cannot be resolved
	// twice. Defaults to a bounded in-memory MemoryReplayCache; use a shared
	// implementation behind a load balancer, exactly as for Options.
	ReplayCache ReplayCache

	// ArtifactTTL is how long a consumed artifact is remembered. Defaults to
	// DefaultArtifactTTL.
	ArtifactTTL time.Duration

	// Clock supplies the current time; nil means time.Now.
	Clock func() time.Time

	// NewID generates ArtifactResolve message IDs. Nil means crypto/rand.
	NewID func() (string, error)

	// MaxResponseBytes caps the back-channel response body. Defaults to 5 MiB.
	MaxResponseBytes int

	// MaxDepth caps XML nesting. Defaults to 100.
	MaxDepth int
}

// ArtifactResolver redeems SAML artifacts over the SOAP back channel. It is safe
// for concurrent use.
type ArtifactResolver struct {
	opts   ArtifactOptions
	certs  []*x509.Certificate
	sigAlg string
	soap   *soapClient
	replay ReplayCache
	ttl    time.Duration
}

// NewArtifactResolver validates opts and returns a resolver.
//
// Configuration problems are reported eagerly, including a missing resolution
// URL and an HTTP client that would skip TLS verification.
func NewArtifactResolver(opts ArtifactOptions) (*ArtifactResolver, error) {
	if opts.EntityID == "" {
		return nil, errors.New("saml: ArtifactOptions.EntityID is required")
	}
	if opts.IdPEntityID == "" {
		return nil, errors.New("saml: ArtifactOptions.IdPEntityID is required to check the artifact SourceID")
	}
	if opts.ArtifactResolutionURL == "" {
		return nil, errors.New("saml: ArtifactOptions.ArtifactResolutionURL is required")
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = defaultMaxResponseBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	r := &ArtifactResolver{
		opts:  opts,
		certs: append([]*x509.Certificate(nil), opts.IdPCertificates...),
		ttl:   opts.ArtifactTTL,
	}
	if len(opts.IdPCertificatePEM) > 0 {
		certs, err := ParseCertificates(opts.IdPCertificatePEM)
		if err != nil {
			return nil, err
		}
		r.certs = append(r.certs, certs...)
	}
	if r.ttl <= 0 {
		r.ttl = DefaultArtifactTTL
	}
	r.replay = opts.ReplayCache
	if r.replay == nil {
		r.replay = &MemoryReplayCache{Clock: r.now}
	}
	var err error
	if r.sigAlg, err = resolveSigAlg(opts.SignatureAlgorithm, opts.SigningKey); err != nil {
		return nil, err
	}
	if r.soap, err = newSOAPClient(opts.HTTPClient, opts.Timeout, opts.MaxResponseBytes, opts.MaxDepth); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ArtifactResolver) now() time.Time {
	if r.opts.Clock != nil {
		return r.opts.Clock()
	}
	return time.Now()
}

func (r *ArtifactResolver) newID() (string, error) {
	if r.opts.NewID != nil {
		return r.opts.NewID()
	}
	return NewMessageID()
}

// ArtifactResponse is a verified samlp:ArtifactResponse.
type ArtifactResponse struct {
	// ID is the ArtifactResponse's own ID attribute.
	ID string
	// InResponseTo is the ID of the ArtifactResolve it answers; it has already
	// been checked against the request this package sent.
	InResponseTo string
	// Issuer is the entity that produced the ArtifactResponse.
	Issuer string
	// IssueInstant is when it was produced, zero when not stated.
	IssueInstant time.Time
	// StatusCode is the ArtifactResponse's own StatusCode, always
	// StatusSuccess for a value that was returned without error.
	StatusCode string
	// Signed reports that the ArtifactResponse carried a signature that
	// verified against a configured certificate.
	Signed bool
	// InnerSigned reports that the samlp:Response inside carried its own
	// verified signature, over the response or over an assertion.
	InnerSigned bool
	// ResponseXML is the extracted samlp:Response, in canonical form. Feed it
	// to Strategy.Validate — or use ResolveAssertion, which does — for the
	// full assertion pipeline.
	ResponseXML []byte
	// Artifact is the artifact that was redeemed.
	Artifact *Artifact
}

// EncodedResponse returns ResponseXML base64-encoded, in the form
// Strategy.Validate expects.
func (a *ArtifactResponse) EncodedResponse() string {
	return base64.StdEncoding.EncodeToString(a.ResponseXML)
}

// Resolve redeems samlArt — the raw value of the SAMLart parameter — and returns
// the verified ArtifactResponse.
//
// The artifact is consumed through the replay cache before the network call, so
// a second Resolve of the same artifact fails without generating traffic, and
// the endpoint used is always ArtifactOptions.ArtifactResolutionURL.
func (r *ArtifactResolver) Resolve(ctx context.Context, samlArt string) (*ArtifactResponse, error) {
	if len(r.certs) == 0 {
		return nil, ErrNoCertificates
	}
	art, err := ParseArtifact(samlArt)
	if err != nil {
		return nil, err
	}
	if err := art.CheckSourceID(r.opts.IdPEntityID); err != nil {
		return nil, err
	}
	// Single use, enforced before anything leaves this process. Doing it after
	// the call would let a replayed artifact be used to hammer the identity
	// provider even though the result is discarded.
	fresh, err := r.replay.Store("artifact:"+art.String(), r.now().Add(r.ttl))
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, fmt.Errorf("%w: artifact has already been resolved", ErrReplay)
	}

	resolveID, err := r.newID()
	if err != nil {
		return nil, err
	}
	message, err := r.buildArtifactResolve(resolveID, art)
	if err != nil {
		return nil, err
	}
	elem, err := r.soap.call(ctx, r.opts.ArtifactResolutionURL, message)
	if err != nil {
		return nil, err
	}
	// Peel the SOAP envelope off before verifying anything. The identity
	// provider signed the ArtifactResponse as a message and then wrapped it for
	// transport, so the document its signature covers is the standalone
	// ArtifactResponse — which, under Canonical XML 1.0, is not the same node
	// set as the one still sitting inside the envelope. Extracting first makes
	// the verified bytes the bytes that were signed.
	raw, err := extractElement(elem)
	if err != nil {
		return nil, err
	}
	root, err := parseXML(raw, r.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	out, err := r.readArtifactResponse(root, resolveID)
	if err != nil {
		return nil, err
	}
	out.Artifact = art
	return out, nil
}

// ResolveAssertion redeems samlArt and runs the recovered samlp:Response through
// s, returning the authenticated assertion. It is the whole HTTP-Artifact flow
// in one call.
func (r *ArtifactResolver) ResolveAssertion(ctx context.Context, samlArt string, s *Strategy) (*Assertion, error) {
	if s == nil {
		return nil, errors.New("saml: nil Strategy")
	}
	res, err := r.Resolve(ctx, samlArt)
	if err != nil {
		return nil, err
	}
	return s.Validate(res.EncodedResponse())
}

// buildArtifactResolve renders the samlp:ArtifactResolve, signing it when a key
// is configured.
func (r *ArtifactResolver) buildArtifactResolve(id string, art *Artifact) (string, error) {
	now := r.now().UTC()
	var sb strings.Builder
	sb.WriteString(`<samlp:ArtifactResolve xmlns:samlp="` + nsSAMLProtocol + `"`)
	sb.WriteString(` xmlns:saml="` + nsSAMLAssertion + `"`)
	sb.WriteString(` ID="` + escapeAttr(id) + `"`)
	sb.WriteString(` Version="2.0"`)
	sb.WriteString(` IssueInstant="` + now.Format(time.RFC3339) + `"`)
	sb.WriteString(` Destination="` + escapeAttr(r.opts.ArtifactResolutionURL) + `">`)
	sb.WriteString(`<saml:Issuer>` + escapeText(r.opts.EntityID) + `</saml:Issuer>`)
	// Schema order for samlp:ArtifactResolve is Issuer, Signature, Extensions,
	// Artifact.
	sb.WriteString(signatureMarker)
	sb.WriteString(`<samlp:Artifact>` + escapeText(art.String()) + `</samlp:Artifact>`)
	sb.WriteString(`</samlp:ArtifactResolve>`)

	tmpl := sb.String()
	if r.opts.SigningKey == nil {
		return strings.Replace(tmpl, signatureMarker, "", 1), nil
	}
	signed, err := signEnveloped(tmpl, id, r.opts.SigningKey, r.opts.SigningCertificate, r.sigAlg, r.opts.MaxDepth)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// readArtifactResponse verifies and reads the samlp:ArtifactResponse returned in
// the SOAP body.
//
// Verification is the same code path an assertion goes through: verifySignature
// locates the element each signature actually covers, and a signature covering
// anything other than the ArtifactResponse is refused rather than counted.
func (r *ArtifactResolver) readArtifactResponse(root *xnode, expectedInResponseTo string) (*ArtifactResponse, error) {
	if !root.is(nsSAMLProtocol, "ArtifactResponse") {
		return nil, fmt.Errorf("saml: soap:Body carries <%s>, expected samlp:ArtifactResponse", root.local)
	}
	out := &ArtifactResponse{}
	var ok bool
	if out.ID, ok = root.attrValue("", "ID"); !ok || out.ID == "" {
		return nil, errors.New("saml: ArtifactResponse has no ID attribute")
	}
	if v, ok := root.attrValue("", "Version"); ok && v != "2.0" {
		return nil, fmt.Errorf("saml: ArtifactResponse Version is %q, expected 2.0", v)
	}
	if v, ok := root.attrValue("", "IssueInstant"); ok {
		var err error
		if out.IssueInstant, err = parseSAMLTime(v); err != nil {
			return nil, err
		}
	}
	out.InResponseTo, _ = root.attrValue("", "InResponseTo")
	if out.InResponseTo != expectedInResponseTo {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrArtifactInResponseTo, out.InResponseTo, expectedInResponseTo)
	}

	// Every signature in the ArtifactResponse subtree that is a direct child of
	// it must verify and must cover it. Signatures deeper down belong to the
	// samlp:Response and are handled with that element.
	signed := false
	for _, sig := range root.childElements(nsDSig, "Signature") {
		verified, err := verifySignature(root, sig, r.certs, r.opts.AllowSHA1)
		if err != nil {
			return nil, err
		}
		if verified.element != root {
			return nil, errors.New("saml: ArtifactResponse signature covers an unexpected element")
		}
		signed = true
	}
	if !signed {
		// A certificate is always configured (Resolve refuses otherwise), so
		// an unsigned ArtifactResponse is always a rejection. The back channel
		// being TLS-protected is not a substitute: TLS authenticates the
		// endpoint, not the message, and the message is what mints a session.
		return nil, fmt.Errorf("%w: samlp:ArtifactResponse is not signed", ErrNoSignature)
	}
	out.Signed = signed

	if issuer, err := root.optionalChild(nsSAMLAssertion, "Issuer"); err != nil {
		return nil, err
	} else if issuer != nil {
		out.Issuer = strings.TrimSpace(issuer.textContent())
	}
	if out.Issuer != "" && out.Issuer != r.opts.IdPEntityID {
		return nil, fmt.Errorf("saml: ArtifactResponse issuer %q is not the configured identity provider %q",
			out.Issuer, r.opts.IdPEntityID)
	}

	status, err := root.onlyChild(nsSAMLProtocol, "Status")
	if err != nil {
		return nil, err
	}
	code, err := status.onlyChild(nsSAMLProtocol, "StatusCode")
	if err != nil {
		return nil, err
	}
	out.StatusCode, _ = code.attrValue("", "Value")
	if out.StatusCode != StatusSuccess {
		msg := out.StatusCode
		if m, _ := status.optionalChild(nsSAMLProtocol, "StatusMessage"); m != nil {
			msg += ": " + strings.TrimSpace(m.textContent())
		}
		return nil, fmt.Errorf("%w (%s)", ErrArtifactStatus, msg)
	}

	inner, err := root.onlyChild(nsSAMLProtocol, "Response")
	if err != nil {
		return nil, fmt.Errorf("saml: ArtifactResponse carries no samlp:Response: %w", err)
	}
	// The samlp:Response is lifted out verbatim rather than canonicalized:
	// canonicalization would rewrite the namespace declarations, and either
	// direction of rewrite breaks a signature. Rendering the in-scope
	// declarations at the apex adds the enclosing message's prefixes, which
	// Canonical XML 1.0 then folds into the digest; rendering only the
	// visibly-utilized ones instead pushes declarations down the tree, which
	// Canonical XML 1.0 also notices. Copying the element out as written leaves
	// every signature over it, and over anything inside it, intact.
	if out.ResponseXML, err = extractElement(inner); err != nil {
		return nil, err
	}
	// Verify the extracted document, for the same reason the ArtifactResponse
	// is extracted before it is verified: this is the samlp:Response the
	// identity provider signed, and it is also the exact byte string
	// Strategy.Validate will re-verify from scratch afterwards.
	innerRoot, err := parseXML(out.ResponseXML, r.opts.MaxDepth)
	if err != nil {
		return nil, err
	}
	if out.InnerSigned, err = r.verifyInnerResponse(innerRoot); err != nil {
		return nil, err
	}
	return out, nil
}

// verifyInnerResponse checks the signatures carried by the samlp:Response inside
// an ArtifactResponse and reports whether it is self-authenticating.
//
// The ArtifactResponse signature already covers these bytes, so this is a
// second, independent line: it makes an unsigned inner response a rejection here
// rather than several layers later, and it means every signature present must
// verify — one that does not is never simply skipped over.
//
// The single documented exception is a response whose assertions are all
// encrypted and carry their signature inside the ciphertext. Nothing here can
// see into that, so the decision is left to Strategy.Validate, which enforces it
// after decryption.
func (r *ArtifactResolver) verifyInnerResponse(inner *xnode) (bool, error) {
	var signatures []*xnode
	inner.walk(func(n *xnode) {
		if n.is(nsDSig, "Signature") {
			signatures = append(signatures, n)
		}
	})
	if len(signatures) == 0 {
		encrypted := false
		inner.walk(func(n *xnode) {
			if n.is(nsSAMLAssertion, "EncryptedAssertion") {
				encrypted = true
			}
		})
		if encrypted {
			return false, nil
		}
		return false, fmt.Errorf("%w: samlp:Response inside the ArtifactResponse is not signed", ErrNoSignature)
	}
	for _, sig := range signatures {
		verified, err := verifySignature(inner, sig, r.certs, r.opts.AllowSHA1)
		if err != nil {
			return false, err
		}
		if verified.element != inner && !(verified.element.is(nsSAMLAssertion, "Assertion") && verified.element.parent == inner) {
			return false, errors.New("saml: signature inside the ArtifactResponse covers an unexpected element")
		}
	}
	return true, nil
}

// extractElement serializes an element as a standalone document, byte for byte
// as it was written: original prefixes, original namespace declarations,
// original attribute order, comments and processing instructions included.
//
// The element must declare every namespace prefix its subtree uses. One that
// leans on a declaration left behind in the SOAP envelope or in the enclosing
// ArtifactResponse is rejected rather than resolved against its surroundings —
// the same rule this package applies to a decrypted assertion, and for the same
// reason. Such a fragment cannot be lifted out without rewriting it, and
// rewriting a document in order to check its signature is how signature checks
// come to disagree with the document that is eventually acted on.
func extractElement(apex *xnode) ([]byte, error) {
	var buf strings.Builder
	if err := writeElement(&buf, apex, map[string]string{}); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// writeElement renders one element and its descendants. scope maps the prefixes
// declared so far *within the extracted subtree*, deliberately not including
// anything inherited from outside it.
func writeElement(buf *strings.Builder, n *xnode, scope map[string]string) error {
	next := scope
	if len(n.ns) > 0 {
		next = make(map[string]string, len(scope)+len(n.ns))
		for k, v := range scope {
			next[k] = v
		}
		for _, d := range n.ns {
			next[d.prefix] = d.uri
		}
	}
	if err := checkExtractable(next, n.prefix, n.uri, "element <"+qname(n.prefix, n.local)+">"); err != nil {
		return err
	}
	for _, a := range n.attrs {
		if a.prefix == "" {
			continue // an unprefixed attribute is in no namespace
		}
		if err := checkExtractable(next, a.prefix, a.uri, "attribute "+qname(a.prefix, a.local)); err != nil {
			return err
		}
	}

	name := qname(n.prefix, n.local)
	buf.WriteByte('<')
	buf.WriteString(name)
	for _, d := range n.ns {
		if d.prefix == "" {
			buf.WriteString(` xmlns="`)
		} else {
			buf.WriteString(" xmlns:")
			buf.WriteString(d.prefix)
			buf.WriteString(`="`)
		}
		buf.WriteString(escapeAttr(d.uri))
		buf.WriteByte('"')
	}
	for _, a := range n.attrs {
		buf.WriteByte(' ')
		buf.WriteString(qname(a.prefix, a.local))
		buf.WriteString(`="`)
		buf.WriteString(escapeAttr(a.value))
		buf.WriteByte('"')
	}
	buf.WriteByte('>')
	for _, ch := range n.children {
		switch ch.kind {
		case nodeElement:
			if err := writeElement(buf, ch, next); err != nil {
				return err
			}
		case nodeText:
			buf.WriteString(escapeText(ch.text))
		case nodeComment:
			if strings.Contains(ch.text, "--") {
				return errors.New("saml: comment inside the samlp:Response cannot be serialized")
			}
			buf.WriteString("<!--" + ch.text + "-->")
		case nodePI:
			buf.WriteString("<?" + ch.piTarget)
			if ch.text != "" {
				buf.WriteString(" " + ch.text)
			}
			buf.WriteString("?>")
		}
	}
	buf.WriteString("</")
	buf.WriteString(name)
	buf.WriteByte('>')
	return nil
}

// checkExtractable reports whether prefix resolves to uri using only the
// declarations made inside the extracted subtree.
func checkExtractable(scope map[string]string, prefix, uri, what string) error {
	if prefix == "xml" {
		if uri == nsXML {
			return nil
		}
		return fmt.Errorf("saml: %s uses a rebound \"xml\" prefix", what)
	}
	declared, ok := scope[prefix]
	if !ok {
		declared = "" // no default namespace and no such prefix
	}
	if declared != uri {
		if prefix == "" {
			return fmt.Errorf("saml: %s relies on a default namespace declared outside the samlp:Response", what)
		}
		return fmt.Errorf("saml: %s relies on the namespace prefix %q declared outside the samlp:Response", what, prefix)
	}
	return nil
}
