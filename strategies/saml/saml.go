// Package saml implements a SAML 2.0 Service Provider (SP) handler for the Web
// Browser SSO Profile using the HTTP POST binding. It ports the server-side
// shape of passport-saml from the Passport.js ecosystem: it reads a
// base64-encoded SAMLResponse form field posted by the identity provider,
// validates it, and maps the asserted subject (the NameID) to an application
// user.
//
// Use this strategy when you integrate with an enterprise SAML identity
// provider (Okta, OneLogin, ADFS, Entra ID, Shibboleth, ...) for single
// sign-on. SAML is the incumbent enterprise SSO protocol; reach for it when a
// customer requires SAML rather than OpenID Connect. If you get to choose, OIDC
// (strategies/openidconnect) is generally simpler for new integrations.
//
// # Flow
//
// The flow is SP-initiated (or IdP-initiated) SSO. In the SP-initiated case the
// user starts at your app, which redirects the browser to the IdP's SSO
// endpoint with an AuthnRequest. The IdP authenticates the user and then POSTs
// a signed SAMLResponse (an auto-submitting HTML form) to your Assertion
// Consumer Service (ACS) endpoint. This strategy is the ACS handler: on that
// POST it pulls the configured form field (Options.Field, default
// "SAMLResponse"), base64-decodes it, validates it, and hands the result to
// Options.Verify.
//
// # What is validated
//
// Every response must pass all of the following, or authentication fails:
//
//   - The XML parses under a strict parser that rejects DOCTYPE and entity
//     declarations outright (XXE and entity-expansion attacks), caps the
//     document size (Options.MaxResponseBytes) and caps nesting depth
//     (Options.MaxDepth).
//   - Every saml:Assertion and saml:EncryptedAssertion is a direct child of the
//     samlp:Response, and there is exactly one of them unless
//     Options.AllowMultipleAssertions is set.
//   - Every ds:Signature in the document verifies against a certificate in
//     Options.IdPCertificates, and each sits directly inside the element its
//     ds:Reference names.
//   - The samlp:StatusCode is Success.
//   - The assertion's Conditions window, AudienceRestriction, the subject
//     confirmation window and Recipient, and the response Destination all
//     check out, within Options.ClockSkew.
//   - The assertion ID has not been seen before (Options.ReplayCache).
//
// Identity is then read only from inside the subtree that a signature actually
// covered, never from the document at large. That inversion — verify a
// signature over a specific element, then read the subject out of *that*
// element — is what makes XML Signature Wrapping structurally impossible rather
// than something the package tries to pattern-match.
//
// SHA-1 and MD5 are rejected for both digests and signatures unless
// Options.AllowSHA1 is set. Reference transforms are restricted to
// enveloped-signature plus one canonicalization transform; XPath and XSLT
// transforms are refused.
//
// # Fail closed
//
// With no certificate configured, every response is rejected
// (ErrNoCertificates). Options.Audience must be configured, and a response that
// carries a Recipient or Destination is rejected unless
// Options.AssertionConsumerServiceURL is configured to compare it against. The
// only way to disable any of this is Options.InsecureSkipSignatureValidation,
// which is documented as unsafe and is off by default.
//
// # Encrypted assertions
//
// saml:EncryptedAssertion and saml:EncryptedID are supported once
// Options.SPDecryptionKeys (or Options.SPDecryptionKeyPEM, or
// Options.SPSharedKeys) is configured; with no key they are rejected
// (ErrNoDecryptionKey), never skipped.
//
// Decryption is emphatically not authentication: the service provider's
// encryption key is public, so anyone can encrypt an assertion to it. A
// decrypted assertion is accepted only when the identity provider's signature
// covers it, by one of exactly two paths — a verified signature over the whole
// samlp:Response, which covers the EncryptedAssertion's ciphertext byte for
// byte, or a verified signature the decrypted saml:Assertion carries itself.
// With neither, the response is rejected. The decrypted bytes are parsed by the
// same strict parser as the outer document and then run through the same
// conditions, audience, recipient, timestamp and replay checks; there is no
// second, weaker path.
//
// Key transport is RSA-OAEP; RSA-PKCS#1 v1.5 is refused unless
// Options.AllowRSA15. Content encryption is AES-GCM; AES-CBC is refused unless
// Options.AllowCBCDecryption. See those fields for why.
//
// # Multiple assertions
//
// A response carrying more than one assertion is rejected unless
// Options.AllowMultipleAssertions is set. When it is, every assertion must be
// covered by a verified signature and must independently pass every condition
// check: one bad assertion rejects the whole response, and the package never
// picks a valid assertion out of a response that also contains an invalid one.
// Assertion.Assertions exposes the full validated set.
//
// # Beyond the assertion consumer
//
// Strategy handles the ACS half of the flow. The rest of the SP protocol
// surface lives alongside it, configured by its own option types rather than by
// Options:
//
//   - RequestBuilder (RequestOptions) builds and signs the samlp:AuthnRequest
//     that starts SP-initiated SSO, over both the HTTP-Redirect and HTTP-POST
//     bindings. Message IDs come from crypto/rand; keep the returned ID to
//     check InResponseTo on the way back.
//   - SLO (SLOOptions) builds and validates Single Logout messages in both
//     directions. An unsigned LogoutRequest is rejected whenever a certificate
//     is configured, so a third party cannot log a user out or forge
//     confirmation of a logout that never happened.
//   - ArtifactResolver (ArtifactOptions) implements the HTTP-Artifact binding:
//     it parses the browser's SAMLart, checks the SourceID identifies the
//     configured IdP, and fetches the message over a SOAP back channel. The
//     resolution URL always comes from configuration or metadata and never from
//     the artifact, so the binding cannot be turned into a request-forgery
//     primitive; artifacts are single-use through the same ReplayCache.
//   - ParseIdPMetadata reads an IdP EntityDescriptor — endpoints, NameID
//     formats and signing certificates — and ApplyTo populates Options from it.
//     Metadata is parsed with the same strict parser as a response, and is
//     signature-verified when MetadataOptions.TrustAnchors is supplied.
//     Unsigned metadata is trust-on-first-use and must be transported securely.
//
// # Limitations
//
// These are rejections, not silent gaps — a response that needs one of them
// fails to authenticate:
//
//   - Canonicalization covers Exclusive XML Canonicalization 1.0 and Canonical
//     XML 1.0/1.1, each with and without comments. Any other algorithm is
//     rejected. With a "#WithComments" algorithm, comments are signed material,
//     so editing one invalidates the signature. The "#WithComments" URIs are
//     accepted as a CanonicalizationMethod but still refused as a reference
//     Transform.
//   - xml:base is honoured, including the C14N 1.1 fix-up that resolves it
//     across omitted ancestors. The one case still rejected rather than
//     approximated is joining a relative reference onto a relative base, which
//     C14N 1.1 specifies only by example.
//   - Signatures may only cover the samlp:Response, the saml:Assertion, or a
//     samlp:ArtifactResponse wrapping one.
//   - XML Encryption is limited to RSA key transport of an AES session key and,
//     when Options.SPSharedKeys is configured, to a pre-shared symmetric key
//     used either as the content key directly or as an RFC 3394 AES-KeyWrap
//     key-encryption key. Diffie-Hellman and ECDH key agreement,
//     xenc:CipherReference, and EncryptedData of Type "#Content" are all
//     rejected. A pre-shared key is a shared secret, so anyone holding it can
//     forge ciphertext; the signature-coverage requirement above is what keeps
//     that from being a login, and it is not relaxed for these keys.
//   - A fragment lifted out of an enclosing document must declare every
//     namespace prefix it uses. That applies to a decrypted assertion and to a
//     samlp:Response carried inside a samlp:ArtifactResponse: one that leans on
//     a declaration left behind in its envelope is rejected rather than
//     resolved against surroundings the signature never covered.
package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/malcolmston/passport"
)

// defaultClockSkew is the tolerance applied to every timestamp comparison.
const defaultClockSkew = time.Minute

// defaultReplayTTL is how long an assertion ID is remembered when the assertion
// states no NotOnOrAfter.
const defaultReplayTTL = 5 * time.Minute

// ErrNoNameID is returned when the verified assertion contains no NameID.
var ErrNoNameID = errors.New("saml: no NameID found in response")

// ErrTooLarge is returned when the encoded response exceeds
// Options.MaxResponseBytes.
var ErrTooLarge = errors.New("saml: SAMLResponse is too large")

// VerifyFunc maps a verified NameID to an application user. When nil, the
// NameID string is used as the user.
type VerifyFunc func(nameID string) (user any, err error)

// VerifyAssertionFunc maps a fully verified assertion to an application user.
// It is the richer alternative to VerifyFunc, giving access to the issuer,
// session index and attribute statement.
type VerifyAssertionFunc func(a *Assertion) (user any, err error)

// Options configures the strategy. The zero value is not usable: at minimum
// IdPCertificates (or IdPCertificatePEM) and Audience must be set, otherwise
// every response is rejected.
type Options struct {
	// Field is the form field carrying the base64 response. Defaults to
	// "SAMLResponse".
	Field string

	// Verify maps the verified NameID to a user. Optional; when both Verify
	// and VerifyAssertion are nil the NameID string is used as the user.
	Verify VerifyFunc

	// VerifyAssertion maps the whole verified assertion to a user. When set
	// it takes precedence over Verify.
	VerifyAssertion VerifyAssertionFunc

	// IdPCertificates are the identity provider's signing certificates.
	// Configure more than one to roll a key over. A signature must verify
	// against one of these; a certificate embedded in the response is only
	// ever used to pick one of these, never trusted on its own.
	IdPCertificates []*x509.Certificate

	// IdPCertificatePEM is an alternative to IdPCertificates accepting one
	// or more concatenated PEM CERTIFICATE blocks. Both may be set; they are
	// merged. A parse failure makes every subsequent Authenticate report an
	// error rather than silently trusting nothing.
	IdPCertificatePEM []byte

	// SPDecryptionKeys are this service provider's private keys, used to
	// unwrap the session key of a saml:EncryptedAssertion or
	// saml:EncryptedID. Configure more than one to roll a key over: each is
	// tried in turn. Only RSA keys can be used for XML Encryption key
	// transport.
	//
	// Holding one of these keys proves nothing about who produced a
	// response — the matching public key is published in SP metadata, so
	// anyone can encrypt to it. A decrypted assertion is still subject to
	// full signature verification; see the package documentation.
	SPDecryptionKeys []crypto.PrivateKey

	// SPDecryptionKeyPEM is an alternative to SPDecryptionKeys accepting one
	// or more concatenated PEM private-key blocks. Both may be set; they are
	// merged. A parse failure makes every subsequent Authenticate report an
	// error rather than silently decrypting nothing.
	SPDecryptionKeyPEM []byte

	// SPSharedKeys are pre-shared AES keys agreed with the identity provider
	// out of band, keyed by the name the identity provider puts in
	// ds:KeyInfo/ds:KeyName. They cover two shapes some deployments use
	// instead of RSA key transport: an xenc:EncryptedData with no
	// xenc:EncryptedKey, where the key here *is* the content key, and an
	// xenc:EncryptedKey wrapped with AES-KeyWrap (RFC 3394,
	// http://www.w3.org/2001/04/xmlenc#kw-aes128 and friends), where the key
	// here is the key-encryption key.
	//
	// Each key must be exactly 16, 24 or 32 bytes, for AES-128, AES-192 or
	// AES-256; any other length is a configuration error reported by
	// ConfigError, and every Authenticate call then fails. Configure several
	// to roll a key over: a message naming one in ds:KeyName selects exactly
	// that key, and one naming none is tried against every configured key of
	// the right length.
	//
	// A map entry keyed "" is a key the identity provider never names; it
	// participates in the unnamed case like any other.
	//
	// SECURITY. A shared secret is not an asymmetric key: everyone holding it
	// can both decrypt *and* encrypt, so being able to decrypt an assertion
	// says nothing at all about who wrote it. Anyone with this key — the
	// identity provider, this service provider, anyone either of them leaked
	// it to, any other SP the same key was issued to — can forge a
	// well-formed encrypted assertion naming any subject. A decrypted
	// assertion is therefore still accepted only when a verified identity
	// provider signature covers it, by the same two paths described in the
	// package documentation. Prefer RSA key transport, which does not have
	// this problem.
	SPSharedKeys map[string][]byte

	// AllowRSA15 permits RSA-PKCS#1 v1.5 key transport
	// (http://www.w3.org/2001/04/xmlenc#rsa-1_5), which is refused by
	// default.
	//
	// UNSAFE. PKCS#1 v1.5 is vulnerable to Bleichenbacher's adaptive
	// chosen-ciphertext attack, and an ACS endpoint is an ideal oracle for
	// it: an attacker can post as many crafted responses as they like and
	// observe which are accepted. This package uses the constant-time
	// session-key form of the decryption to blunt that, but the mode should
	// simply not be used. Enable it only for an identity provider that
	// cannot be reconfigured, and prefer to fix the identity provider.
	AllowRSA15 bool

	// AllowCBCDecryption permits AES-CBC content encryption
	// (http://www.w3.org/2001/04/xmlenc#aes128-cbc and friends), which is
	// refused by default in favour of AES-GCM.
	//
	// UNSAFE. AES-CBC in XML Encryption has no integrity protection, which
	// is what makes it the target of the Jager–Somorovsky padding-oracle
	// attack (CCS 2011): an attacker who can submit ciphertexts and
	// distinguish outcomes can decrypt an assertion byte by byte. This
	// package answers every CBC failure — bad padding, non-XML plaintext,
	// plaintext that is not an assertion, a signature that does not
	// verify — with one identical ErrDecryptFailed, which removes the
	// message-based distinguisher.
	//
	// Residual risk, stated honestly: the time spent parsing a plaintext
	// that happens to be well-formed XML differs from the time spent
	// rejecting one that is not, and this package does not equalise it. A
	// patient attacker with a low-noise network path may still be able to
	// build a timing oracle. The risk is closed entirely when the identity
	// provider signs the whole samlp:Response, because the ciphertext is
	// then covered by a signature the attacker cannot forge and no crafted
	// ciphertext ever reaches the decryption code.
	AllowCBCDecryption bool

	// MaxDecryptedBytes caps the plaintext a single EncryptedData may
	// produce. Defaults to 1 MiB.
	MaxDecryptedBytes int

	// AllowMultipleAssertions permits a response carrying more than one
	// assertion, which is rejected by default.
	//
	// When set, every assertion — plaintext or encrypted — must be covered
	// by a verified signature and must independently satisfy every
	// condition, audience, recipient, timestamp and replay check. A single
	// assertion that fails rejects the whole response; a valid assertion is
	// never selected out of a response that also contains an invalid one,
	// because that selection is precisely the XML Signature Wrapping shape.
	//
	// When more than one validated assertion carries a different NameID the
	// response is ambiguous and is rejected unless SelectAssertion resolves
	// it.
	AllowMultipleAssertions bool

	// SelectAssertion chooses which of several validated assertions carries
	// the identity. It is called only when AllowMultipleAssertions is set
	// and the response yielded more than one assertion, and only after every
	// one of them has been fully validated. Returning nil, or an assertion
	// that is not in the slice, rejects the response.
	SelectAssertion func(assertions []*Assertion) (*Assertion, error)

	// Audience is this service provider's entity ID. The assertion's
	// AudienceRestriction must name it. Required.
	Audience string

	// AssertionConsumerServiceURL is the absolute URL the IdP posts to. When
	// set, the assertion's Recipient and the response's Destination must
	// equal it. When unset, a response carrying either is rejected.
	AssertionConsumerServiceURL string

	// ValidateInResponseTo, when set, is called with the assertion's
	// InResponseTo (empty for IdP-initiated sign-on) and must return true
	// for the response to be accepted. Use it to match the response against
	// an AuthnRequest ID your application issued and has not yet consumed.
	ValidateInResponseTo func(inResponseTo string) bool

	// Clock supplies the current time; nil means time.Now. Injecting a clock
	// makes timestamp handling testable.
	Clock func() time.Time

	// ClockSkew is the tolerance applied to NotBefore/NotOnOrAfter.
	// Defaults to one minute. A negative value disables the tolerance.
	ClockSkew time.Duration

	// ReplayCache records consumed assertion IDs. Defaults to a bounded
	// in-memory MemoryReplayCache, which is sufficient for a single-process
	// deployment; use a shared implementation behind a load balancer.
	ReplayCache ReplayCache

	// AllowSHA1 permits SHA-1 digests and signatures, which are rejected by
	// default. Some long-lived identity providers still emit them. SHA-1 is
	// collision-broken; enable this only when the IdP cannot be upgraded.
	AllowSHA1 bool

	// MaxResponseBytes caps the size of the decoded XML. Defaults to 5 MiB.
	MaxResponseBytes int

	// MaxDepth caps XML element nesting. Defaults to 100.
	MaxDepth int

	// InsecureSkipSignatureValidation disables the ENTIRE validation
	// pipeline — signature, status, conditions, audience, recipient and
	// replay checks — and falls back to reading the first NameID found
	// anywhere in the document. Anyone who can reach the ACS endpoint can
	// then authenticate as any user by posting a hand-written XML document.
	// It exists only for local development against a mock identity provider
	// and must never be set in production.
	InsecureSkipSignatureValidation bool
}

// Strategy consumes a SAMLResponse, validates it, and authenticates the
// subject.
type Strategy struct {
	field           string
	verify          VerifyFunc
	verifyAssertion VerifyAssertionFunc

	certs     []*x509.Certificate
	audience  string
	acsURL    string
	allowSHA1 bool
	insecure  bool

	spKeys        []crypto.PrivateKey
	sharedKeys    map[string][]byte
	allowRSA15    bool
	allowCBC      bool
	maxDecrypted  int
	allowMultiple bool
	selectFn      func([]*Assertion) (*Assertion, error)

	clock                func() time.Time
	skew                 time.Duration
	replay               ReplayCache
	validateInResponseTo func(string) bool

	maxBytes int
	maxDepth int

	configErr error
}

// New creates a Strategy from opts.
//
// Configuration problems (an unparsable certificate PEM, for instance) are not
// reported here — New has no error return in the upstream API — but are
// recorded and surfaced as an error from every Authenticate call, so a
// misconfigured strategy fails closed rather than open. ConfigError exposes the
// same problem eagerly.
func New(opts Options) *Strategy {
	s := &Strategy{
		field:                opts.Field,
		verify:               opts.Verify,
		verifyAssertion:      opts.VerifyAssertion,
		certs:                append([]*x509.Certificate(nil), opts.IdPCertificates...),
		audience:             opts.Audience,
		acsURL:               opts.AssertionConsumerServiceURL,
		allowSHA1:            opts.AllowSHA1,
		insecure:             opts.InsecureSkipSignatureValidation,
		clock:                opts.Clock,
		skew:                 opts.ClockSkew,
		replay:               opts.ReplayCache,
		validateInResponseTo: opts.ValidateInResponseTo,
		maxBytes:             opts.MaxResponseBytes,
		maxDepth:             opts.MaxDepth,
		spKeys:               append([]crypto.PrivateKey(nil), opts.SPDecryptionKeys...),
		allowRSA15:           opts.AllowRSA15,
		allowCBC:             opts.AllowCBCDecryption,
		maxDecrypted:         opts.MaxDecryptedBytes,
		allowMultiple:        opts.AllowMultipleAssertions,
		selectFn:             opts.SelectAssertion,
	}
	if s.field == "" {
		s.field = "SAMLResponse"
	}
	if s.skew == 0 {
		s.skew = defaultClockSkew
	}
	if s.skew < 0 {
		s.skew = 0
	}
	if s.replay == nil {
		// The default cache shares the strategy's clock, so an injected
		// clock governs entry expiry as well as the assertion window.
		s.replay = &MemoryReplayCache{Clock: s.now}
	}
	if s.maxBytes <= 0 {
		s.maxBytes = defaultMaxResponseBytes
	}
	if s.maxDepth <= 0 {
		s.maxDepth = defaultMaxDepth
	}
	if s.maxDecrypted <= 0 {
		s.maxDecrypted = defaultMaxDecryptedBytes
	}
	if len(opts.IdPCertificatePEM) > 0 {
		certs, err := ParseCertificates(opts.IdPCertificatePEM)
		if err != nil {
			s.configErr = err
		} else {
			s.certs = append(s.certs, certs...)
		}
	}
	if len(opts.SPSharedKeys) > 0 {
		// Copied so a later mutation of the caller's map cannot change which
		// keys a running strategy accepts.
		s.sharedKeys = make(map[string][]byte, len(opts.SPSharedKeys))
		names := make([]string, 0, len(opts.SPSharedKeys))
		for name := range opts.SPSharedKeys {
			names = append(names, name)
		}
		// Sorted so a bad configuration reports the same key every time
		// rather than whichever the map iteration reached first.
		sort.Strings(names)
		for _, name := range names {
			key := opts.SPSharedKeys[name]
			switch len(key) {
			case 16, 24, 32:
			default:
				// Fail closed: a key of the wrong length can never decrypt
				// anything, and silently ignoring it would look like a
				// working configuration until the first encrypted response.
				if s.configErr == nil {
					s.configErr = fmt.Errorf("saml: pre-shared key %q is %d bytes; AES needs 16, 24 or 32 (Options.SPSharedKeys)", name, len(key))
				}
			}
			s.sharedKeys[name] = append([]byte(nil), key...)
		}
	}
	if len(opts.SPDecryptionKeyPEM) > 0 {
		keys, err := ParsePrivateKeys(opts.SPDecryptionKeyPEM)
		if err != nil {
			if s.configErr == nil {
				s.configErr = err
			}
		} else {
			s.spKeys = append(s.spKeys, keys...)
		}
	}
	return s
}

// ParseCertificates parses one or more concatenated PEM CERTIFICATE blocks. It
// is the helper behind Options.IdPCertificatePEM and is exported so callers can
// validate their configuration at start-up.
func ParseCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("saml: unexpected PEM block %q, want CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("saml: parsing IdP certificate: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("saml: no CERTIFICATE block found in PEM input")
	}
	return out, nil
}

// ConfigError reports a problem with the Options the strategy was built from,
// or nil. A non-nil result means every Authenticate call will fail.
func (s *Strategy) ConfigError() error { return s.configErr }

// Name returns "saml".
func (s *Strategy) Name() string { return "saml" }

func (s *Strategy) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// Validate decodes and fully validates a base64-encoded SAMLResponse and
// returns the verified assertion. It is what Authenticate runs, exposed so that
// non-passport callers — and tests — can use the validator directly.
//
// Validate consumes the assertion ID through the replay cache, so calling it
// twice with the same response fails the second time by design.
func (s *Strategy) Validate(samlResponseBase64 string) (*Assertion, error) {
	if s.insecure {
		nameID, err := ExtractNameID(samlResponseBase64)
		if err != nil {
			return nil, err
		}
		return &Assertion{NameID: nameID}, nil
	}
	raw, err := s.decode(samlResponseBase64)
	if err != nil {
		return nil, err
	}
	return s.validateXML(raw)
}

// decode base64-decodes the response, refusing anything over the size cap
// before allocating for it.
func (s *Strategy) decode(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	// 4 base64 characters carry 3 bytes; reject oversize input up front so a
	// huge POST body is never expanded in memory.
	if len(b64)/4*3 > s.maxBytes {
		return nil, ErrTooLarge
	}
	raw, err := decodeBase64(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) > s.maxBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// ExtractNameID base64-decodes a SAMLResponse and returns the text of the first
// element whose local name is "NameID", accepting both standard and raw
// (unpadded) base64.
//
// SECURITY: this helper performs NO validation whatsoever — no signature check,
// no conditions, no replay protection — and reads the NameID from anywhere in
// the document, so it is trivially forgeable and is the exact pattern XML
// Signature Wrapping exploits. It is retained for inspecting and debugging
// responses, and is used by Authenticate only when
// Options.InsecureSkipSignatureValidation is set. Never make an authorization
// decision from its result. Use Strategy.Validate instead.
func ExtractNameID(b64 string) (string, error) {
	raw, err := decodeBase64(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
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

// Authenticate implements passport.Strategy. A missing form field, a response
// that fails any validation step, and a Verify func that returns a nil user all
// produce a 401 failure; only a Verify func returning an error, or a strategy
// misconfiguration, produces an internal error.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	if s.configErr != nil {
		c.Error(s.configErr)
		return
	}
	_ = r.ParseForm()
	b64 := r.PostFormValue(s.field)
	if b64 == "" {
		b64 = r.FormValue(s.field)
	}
	if b64 == "" {
		c.Fail("missing SAMLResponse", http.StatusUnauthorized)
		return
	}

	assertion, err := s.Validate(b64)
	if err != nil {
		// The challenge is intentionally generic: which check failed is
		// information the poster of the response should not receive.
		c.Fail("invalid SAMLResponse", http.StatusUnauthorized)
		return
	}

	switch {
	case s.verifyAssertion != nil:
		user, err := s.verifyAssertion(assertion)
		if err != nil {
			c.Error(err)
			return
		}
		if user == nil {
			c.Fail("", http.StatusUnauthorized)
			return
		}
		c.Success(user)
	case s.verify != nil:
		user, err := s.verify(assertion.NameID)
		if err != nil {
			c.Error(err)
			return
		}
		if user == nil {
			c.Fail("", http.StatusUnauthorized)
			return
		}
		c.Success(user)
	default:
		c.Success(assertion.NameID)
	}
}
