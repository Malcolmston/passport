# saml — SAML 2.0 Service Provider (SP) handler for the Web Browser SSO Profile using the HTTP

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/saml.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/saml)

Package saml implements a SAML 2.0 Service Provider (SP) handler for the Web
Browser SSO Profile using the HTTP POST binding. It ports the server-side
shape of passport-saml from the Passport.js ecosystem: it reads a
base64-encoded SAMLResponse form field posted by the identity provider,
validates it, and maps the asserted subject (the NameID) to an application
user.

Use this strategy when you integrate with an enterprise SAML identity provider
(Okta, OneLogin, ADFS, Entra ID, Shibboleth, ...) for single sign-on. SAML is
the incumbent enterprise SSO protocol; reach for it when a customer requires
SAML rather than OpenID Connect. If you get to choose, OIDC
(strategies/openidconnect) is generally simpler for new integrations.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/saml"
```

## Usage

This is the package's own `ExampleMemoryReplayCache`, so it compiles and its output is
asserted on every `go test ./saml/`.

```go
cache := saml.NewMemoryReplayCache(1000)
	expires := time.Now().Add(5 * time.Minute)

	first, _ := cache.Store("_assertion-id-1", expires)
	second, _ := cache.Store("_assertion-id-1", expires)
	other, _ := cache.Store("_assertion-id-2", expires)

	fmt.Println(first, second, other)
```

```
true false true
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func DeflateDecode(b64 string, maxBytes int) ([]byte, error)` | DeflateDecode reverses DeflateEncode, refusing to inflate more than maxBytes. |
| `func DeflateEncode(msg []byte) (string, error)` | DeflateEncode DEFLATE-compresses and base64-encodes a SAML message for the HTTP-Redirect binding. |
| `func ExtractNameID(b64 string) (string, error)` | ExtractNameID base64-decodes a SAMLResponse and returns the text of the first element whose local name is "NameID", accepting both standard and raw… |
| `func GenerateSPMetadata(opts SPMetadataOptions) ([]byte, error)` | GenerateSPMetadata renders an md:EntityDescriptor describing this service provider. |
| `func NewMessageID() (string, error)` | NewMessageID returns a fresh SAML message ID: an "_" followed by 32 hex characters of crypto/rand output. |
| `func ParseCertificates(pemBytes []byte) ([]*x509.Certificate, error)` | ParseCertificates parses one or more concatenated PEM CERTIFICATE blocks. |
| `func ParsePrivateKeys(pemBytes []byte) ([]crypto.PrivateKey, error)` | ParsePrivateKeys parses one or more concatenated PEM private-key blocks ("PRIVATE KEY" for PKCS#8, "RSA PRIVATE KEY" for PKCS#1, "EC PRIVATE KEY" for… |
| `func SourceIDFor(entityID string) [20]byte` | SourceIDFor returns the SourceID a type 0x0004 artifact carries for the given entity ID: the SHA-1 of its UTF-8 octets, per SAML 2.0 Bindings 3.6.4.2. |

### Types

| Type | What it is |
| --- | --- |
| `Artifact` | Artifact is a parsed SAML 2.0 type 0x0004 artifact. |
| `ArtifactOptions` | ArtifactOptions configures artifact resolution. |
| `ArtifactResolver` | ArtifactResolver redeems SAML artifacts over the SOAP back channel. |
| `ArtifactResponse` | ArtifactResponse is a verified samlp:ArtifactResponse. |
| `Assertion` | Assertion is the subject information extracted from a SAML assertion whose signature has been verified. |
| `AuthnRequest` | AuthnRequest is a built samlp:AuthnRequest. |
| `Endpoint` | Endpoint is a metadata endpoint: an md:SingleSignOnService, md:SingleLogoutService or md:AssertionConsumerService. |
| `IdPMetadata` | IdPMetadata is the parsed content of an identity provider's md:IDPSSODescriptor. |
| `LogoutRequest` | LogoutRequest is a validated samlp:LogoutRequest. |
| `LogoutResponse` | LogoutResponse is a validated samlp:LogoutResponse. |
| `MemoryReplayCache` | MemoryReplayCache is the default ReplayCache: a concurrency-safe in-memory map that is bounded both by entry expiry and by MaxEntries. |
| `Message` | Message is a protocol message this package produced, ready to be handed to one of the bindings. |
| `MetadataOptions` | MetadataOptions configures ParseIdPMetadata. |
| `Options` | Options configures the strategy. |
| `PostBinding` | PostBinding is a message rendered for the HTTP-POST binding: the values a browser must submit, plus the endpoint to submit them to. |
| `ReplayCache` | ReplayCache records the IDs of assertions that have already been accepted so that a captured SAMLResponse cannot be posted twice. |
| `RequestBuilder` | RequestBuilder produces AuthnRequests. |
| `RequestOptions` | RequestOptions configures the construction of AuthnRequests. |
| `SLO` | SLO implements the SAML 2.0 Single Logout profile for a service provider. |
| `SLOOptions` | SLOOptions configures single logout. |
| `SOAPFault` | SOAPFault is a soap:Fault returned by the identity provider. |
| `SPMetadataOptions` | SPMetadataOptions describes the service provider metadata document to generate for an identity provider to consume. |
| `Strategy` | Strategy consumes a SAMLResponse, validates it, and authenticates the subject. |
| `VerifyAssertionFunc` | VerifyAssertionFunc maps a fully verified assertion to an application user. |
| `VerifyFunc` | VerifyFunc maps a verified NameID to an application user. |
| `XSDuration` | XSDuration is a parsed xs:duration, the type SAML metadata uses for cacheDuration. |

<details>
<summary><code>Artifact</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewArtifact(entityID string, endpointIndex uint16) (*Artifact, error)` | NewArtifact builds a type 0x0004 artifact for entityID with a fresh crypto/rand MessageHandle. |
| `func ParseArtifact(samlArt string) (*Artifact, error)` | ParseArtifact decodes a base64 SAMLart parameter. |
| `func (a *Artifact) CheckSourceID(entityID string) error` | CheckSourceID reports whether the artifact was issued by entityID, comparing in constant time. |
| `func (a *Artifact) String() string` | String returns the base64 SAMLart parameter value. |

</details>

<details>
<summary><code>ArtifactResolver</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewArtifactResolver(opts ArtifactOptions) (*ArtifactResolver, error)` | NewArtifactResolver validates opts and returns a resolver. |
| `func (r *ArtifactResolver) Resolve(ctx context.Context, samlArt string) (*ArtifactResponse, error)` | Resolve redeems samlArt — the raw value of the SAMLart parameter — and returns the verified ArtifactResponse. |
| `func (r *ArtifactResolver) ResolveAssertion(ctx context.Context, samlArt string, s *Strategy) (*Assertion, error)` | ResolveAssertion redeems samlArt and runs the recovered samlp:Response through s, returning the authenticated assertion. |

</details>

<details>
<summary><code>ArtifactResponse</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (a *ArtifactResponse) EncodedResponse() string` | EncodedResponse returns ResponseXML base64-encoded, in the form Strategy.Validate expects. |

</details>

<details>
<summary><code>IdPMetadata</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseIdPMetadata(data []byte, opts MetadataOptions) (*IdPMetadata, error)` | ParseIdPMetadata parses an md:EntityDescriptor or md:EntitiesDescriptor and returns the identity provider role it describes. |
| `func (m *IdPMetadata) ApplyTo(o *Options)` | ApplyTo populates the IdP-derived fields of an ACS Options: the signing certificates. |
| `func (m *IdPMetadata) ApplyToArtifactOptions(o *ArtifactOptions, index int) error` | ApplyToArtifactOptions sets the IdP-derived fields of an ArtifactOptions: the IdP entity ID, its signing certificates and the artifact resolution… |
| `func (m *IdPMetadata) ApplyToRequestOptions(o *RequestOptions, binding string) error` | ApplyToRequestOptions sets the AuthnRequest destination from the metadata, choosing the SingleSignOnService endpoint for the given binding — the… |
| `func (m *IdPMetadata) ApplyToSLOOptions(o *SLOOptions, binding string) error` | ApplyToSLOOptions sets the IdP-derived fields of an SLOOptions: the expected issuer, the signing certificates and the SLO endpoint for the given… |
| `func (m *IdPMetadata) ArtifactResolutionURL(index int) string` | ArtifactResolutionURL returns the Location of the md:ArtifactResolutionService with the given index, or "" when the IdP publishes none with that… |
| `func (m *IdPMetadata) SLOResponseURL(binding string) string` | SLOResponseURL returns the SingleLogoutService ResponseLocation for the given binding, falling back to its Location. |
| `func (m *IdPMetadata) SLOURL(binding string) string` | SLOURL returns the SingleLogoutService Location for the given binding, or "" when the IdP does not publish one. |
| `func (m *IdPMetadata) SSOURL(binding string) string` | SSOURL returns the SingleSignOnService Location for the given binding, or "" when the IdP does not publish one. |

</details>

<details>
<summary><code>MemoryReplayCache</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache` | NewMemoryReplayCache returns an empty MemoryReplayCache holding at most maxEntries unexpired IDs. |
| `func (c *MemoryReplayCache) Len() int` | Len reports how many entries are currently held, expired ones included. |
| `func (c *MemoryReplayCache) Store(id string, expires time.Time) (bool, error)` | Store implements ReplayCache. |

</details>

<details>
<summary><code>PostBinding</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (p *PostBinding) FormValues() url.Values` | FormValues returns the POST body parameters. |
| `func (p *PostBinding) HTMLForm() string` | HTMLForm renders a self-submitting HTML form, which is how the POST binding is delivered through a browser. |

</details>

<details>
<summary><code>RequestBuilder</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewRequestBuilder(opts RequestOptions) (*RequestBuilder, error)` | NewRequestBuilder validates opts and returns a builder. |
| `func (b *RequestBuilder) BuildAuthnRequest() (*AuthnRequest, error)` | BuildAuthnRequest constructs a new AuthnRequest with a fresh random ID. |
| `func (b *RequestBuilder) PostBinding(req *AuthnRequest, relayState string) (*PostBinding, error)` | PostBinding renders req for the HTTP-POST binding. |
| `func (b *RequestBuilder) RedirectURL(req *AuthnRequest, relayState string) (string, error)` | RedirectURL renders req for the HTTP-Redirect binding and returns the absolute URL to send the browser to. |

</details>

<details>
<summary><code>SLO</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewSLO(opts SLOOptions) (*SLO, error)` | NewSLO validates opts and returns a single logout handler. |
| `func (s *SLO) BuildLogoutRequest(nameID, nameIDFormat string, sessionIndexes ...string) (*Message, error)` | BuildLogoutRequest constructs an SP-initiated samlp:LogoutRequest for the given subject. |
| `func (s *SLO) BuildLogoutResponse(req *LogoutRequest) (*Message, error)` | BuildLogoutResponse constructs a Success samlp:LogoutResponse answering req. |
| `func (s *SLO) BuildLogoutResponseStatus(req *LogoutRequest, statusCode, statusMessage string) (*Message, error)` | BuildLogoutResponseStatus constructs a samlp:LogoutResponse answering req with an explicit top-level status code. |
| `func (s *SLO) PostBinding(m *Message, relayState string) (*PostBinding, error)` | PostBinding renders m for the HTTP-POST binding with an enveloped XML signature. |
| `func (s *SLO) RedirectURL(m *Message, relayState string) (string, error)` | RedirectURL renders m for the HTTP-Redirect binding, signing the query string when a signing key is configured. |
| `func (s *SLO) ValidateLogoutRequestPOST(samlRequestBase64, relayState string) (*LogoutRequest, error)` | ValidateLogoutRequestPOST validates a base64-encoded samlp:LogoutRequest received over the HTTP-POST binding. |
| `func (s *SLO) ValidateLogoutRequestRedirect(rawQuery string) (*LogoutRequest, error)` | ValidateLogoutRequestRedirect validates a samlp:LogoutRequest received over the HTTP-Redirect binding. |
| `func (s *SLO) ValidateLogoutResponsePOST(samlResponseBase64, expectedInResponseTo, relayState string) (*LogoutResponse, error)` | ValidateLogoutResponsePOST validates a base64-encoded samlp:LogoutResponse received over the HTTP-POST binding. |
| `func (s *SLO) ValidateLogoutResponseRedirect(rawQuery, expectedInResponseTo string) (*LogoutResponse, error)` | ValidateLogoutResponseRedirect validates a samlp:LogoutResponse received over the HTTP-Redirect binding. |

</details>

<details>
<summary><code>SOAPFault</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (f *SOAPFault) Error() string` | Error implements error. |
| `func (f *SOAPFault) Unwrap() error` | Unwrap makes errors.Is(err, ErrSOAPFault) report true for any fault. |

</details>

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) ConfigError() error` | ConfigError reports a problem with the Options the strategy was built from, or nil. |
| `func (s *Strategy) Name() string` | Name returns "saml". |
| `func (s *Strategy) Validate(samlResponseBase64 string) (*Assertion, error)` | Validate decodes and fully validates a base64-encoded SAMLResponse and returns the verified assertion. |

</details>

<details>
<summary><code>XSDuration</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseXSDuration(s string) (XSDuration, error)` | ParseXSDuration parses an xs:duration: an optional "-", then "P", then any non-empty selection of nY, nM, nD, and after a "T" any non-empty selection… |
| `func (d XSDuration) AddTo(t time.Time) time.Time` | AddTo applies the duration to t and returns the result. |
| `func (d XSDuration) ApproximateDuration() time.Duration` | ApproximateDuration converts the whole duration to a time.Duration by valuing a year at 365.2425 days and a month at a twelfth of that, 30.436875… |
| `func (d XSDuration) IsZero() bool` | IsZero reports whether the duration is zero-length, i.e. |
| `func (d XSDuration) Present() bool` | Present reports whether the value came from an actual xs:duration rather than being a zero value standing in for an absent attribute. |
| `func (d XSDuration) String() string` | String returns the lexical form the value was parsed from, or the canonical rendering of a value constructed by hand. |

</details>

### Constants

`BindingHTTPRedirect`, `BindingHTTPPost`, `BindingHTTPArtifact`, `BindingSOAP`, `NameIDFormatUnspecified`, `NameIDFormatEmailAddress`, `NameIDFormatPersistent`, `NameIDFormatTransient`, `NameIDFormatEntity`, `ComparisonExact`, `ComparisonMinimum`, `ComparisonMaximum`, `ComparisonBetter`, `SigAlgRSASHA256`, `SigAlgRSASHA384`, `SigAlgRSASHA512`, `SigAlgECDSASHA256`, `SigAlgECDSASHA384`, `SigAlgECDSASHA512`, `AlgC14N`, `AlgC14NWithComments`, `AlgC14N11`, `AlgC14N11WithComments`, `AlgC14NExclusive`, `AlgC14NExclusiveWithComments`, `AlgEnvelopedSignature`, `StatusRequester`, `StatusResponder`, `StatusPartialLogout`, `AlgRSAOAEPMGF1P`, `AlgRSAOAEP`, `AlgRSA15`, `AlgAESKW128`, `AlgAESKW192`, `AlgAESKW256`, `AlgAES128GCM`, `AlgAES192GCM`, `AlgAES256GCM`, `AlgAES128CBC`, `AlgAES192CBC`, `AlgAES256CBC`, `ArtifactLength`, `ArtifactTypeCode0004`, `DefaultArtifactTTL`, `DefaultReplayCacheMaxEntries`, `DefaultSOAPTimeout`, `SOAPAction`, `StatusSuccess`

### Variables

`ErrMalformedArtifact`, `ErrArtifactSourceID`, `ErrArtifactStatus`, `ErrArtifactInResponseTo`, `ErrNoSigningKey`, `ErrMissingSignature`, `ErrDuplicateParameter`, `ErrNoEntityDescriptor`, `ErrNoIDPDescriptor`, `ErrNoSSOService`, `ErrNoSigningCertificate`, `ErrMetadataExpired`, `ErrLogoutStatus`, `ErrInResponseTo`, `ErrStatus`, `ErrConditions`, `ErrEncrypted`, `ErrAmbiguousAssertion`, `ErrNoCertificates`, `ErrNoSignature`, `ErrSignatureInvalid`, `ErrWeakAlgorithm`, `ErrUntrustedCertificate`, `ErrNoDecryptionKey`, `ErrNoSharedKey`, `ErrDecryptFailed`, `ErrDecryptedTooLarge`, `ErrDoctype`, `ErrInsecureTLS`, `ErrMalformedDuration`, `ErrNoNameID`, `ErrReplay`, `ErrReplayCacheFull`, `ErrSOAPFault`, `ErrTooLarge`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/saml).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
