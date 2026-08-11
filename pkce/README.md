# pkce — implements Proof Key for Code Exchange (PKCE, RFC 7636) for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/pkce.svg)](https://pkg.go.dev/github.com/malcolmston/passport/pkce)
[![Parity](https://img.shields.io/badge/parity-100%25-brightgreen)](https://github.com/malcolmston/go/tree/main/parity/passport/nested/pkce)

Package pkce implements Proof Key for Code Exchange (PKCE, RFC 7636) for the
passport port. PKCE hardens the OAuth 2.0 authorization-code grant against
authorization-code interception attacks and is mandatory for public clients
(native and single-page apps). The strategies/oauth2 base deliberately omits
PKCE; this package supplies the missing primitives so callers can layer it on
top of any OAuth2 provider preset.

The flow adds two values to the standard authorization-code exchange. Before
redirecting the user agent to the provider, the client generates a high-
entropy, URL-safe code verifier and derives a code challenge from it. The
challenge (and the transformation method, "S256" or "plain") travels on the
authorization request; the raw verifier is retained locally. When the provider
redirects back with an authorization code, the client sends the verifier along
with the code to the token endpoint, and the server confirms that the
previously seen challenge matches the transformed verifier.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/pkce"
```

## Usage

This is the package's own `Example`, so it compiles and its output is
asserted on every `go test ./pkce/`.

```go
pair, err := pkce.New()
	if err != nil {
		panic(err)
	}

	auth := pair.AuthParams()
	fmt.Println("method:", auth["code_challenge_method"])

	fmt.Println("token request carries:", len(pair.TokenParams()), "parameter")

	fmt.Println("verified:", pkce.Verify(pair.Method, pair.Verifier, pair.Challenge))
```

```
method: S256
token request carries: 1 parameter
verified: true
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func ComputeChallenge(method Method, verifier string) (string, error)` | ComputeChallenge derives the code challenge for verifier under method. |
| `func GenerateVerifier() (string, error)` | GenerateVerifier returns a cryptographically random code verifier built from 32 bytes of entropy, yielding a 43-character URL-safe string — the… |
| `func PlainChallenge(verifier string) string` | PlainChallenge returns the "plain" code challenge, which is the verifier unchanged. |
| `func S256Challenge(verifier string) string` | S256Challenge returns the SHA-256 code challenge for verifier: BASE64URL-ENCODE(SHA256(ASCII(verifier))), without padding. |
| `func ValidVerifier(v string) bool` | ValidVerifier reports whether v is a syntactically valid code verifier: 43 to 128 characters drawn from the unreserved set [A-Za-z0-9-._~]. |
| `func VerifierWithLength(n int) (string, error)` | VerifierWithLength returns a random code verifier derived from n bytes of entropy. |
| `func Verify(method Method, verifier, challenge string) bool` | Verify reports whether verifier matches challenge under method, using a constant-time comparison. |

### Types

| Type | What it is |
| --- | --- |
| `Method` | Method identifies a PKCE code-challenge transformation. |
| `Pair` | Pair bundles a verifier with its derived challenge and the transformation method that connects them. |

<details>
<summary><code>Method</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseMethod(s string) (Method, error)` | ParseMethod interprets a code_challenge_method value from an authorization request. |
| `func (m Method) String() string` | String returns the wire representation of the method ("S256" or "plain"). |
| `func (m Method) Valid() bool` | Valid reports whether m is one of the two RFC 7636 transformations. |

</details>

<details>
<summary><code>Pair</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New() (Pair, error)` | New returns a fresh Pair using the S256 transformation. |
| `func NewWithMethod(method Method) (Pair, error)` | NewWithMethod returns a fresh Pair using the given transformation. |
| `func (p Pair) AuthParams() map[string]string` | AuthParams returns the query parameters a client adds to the authorization request: code_challenge and code_challenge_method. |
| `func (p Pair) TokenParams() map[string]string` | TokenParams returns the form parameters a client adds to the authorization- code token request: the single code_verifier field (RFC 7636 Section 4.5). |
| `func (p Pair) Valid() bool` | Valid reports whether p is internally consistent: the verifier is syntactically legal and the challenge is exactly what Method derives from it. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/pkce).

## Measured parity

Compared case-for-case against **`pkce-challenge@6.0.0`** by the harness in
[`parity/passport/nested/pkce`](https://github.com/malcolmston/go/tree/main/parity/passport/nested/pkce):

| | |
| --- | --- |
| Parity | **100%** |
| Cases | 49 |
| Matching | 42 |
| Mismatching | 0 |
| Declared deviations | 7 |

Regenerate from the aggregator repo with `go test ./parity/passport/nested/pkce/`.
Declared deviations are documented differences, excluded from the denominator
and listed in the harness report.

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
