# httpauth — This file adds HTTP Digest Access Authentication (RFC 7616) to the httpauth package

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/httpauth.svg)](https://pkg.go.dev/github.com/malcolmston/passport/httpauth)
[![Parity](https://img.shields.io/badge/parity-100%25-brightgreen)](https://github.com/malcolmston/go/tree/main/parity/passport/nested/httpauth)

This file adds HTTP Digest Access Authentication (RFC 7616) to the httpauth
package. The response-digest computation follows RFC 7616 Section 3.4.6
exactly and is verified against the canonical worked example in RFC 7616
Section 3.9.1 (see httpauth_parity_test.go). Only the standard library is
used; the crypto/* hashes are the ones the specification names.

Package httpauth encodes and decodes HTTP Authorization and WWW-Authenticate
headers for the passport port. The basic, bearer, and digest strategies each
parse these headers themselves; this package factors the wire-format handling
into one standard-library-only place with exact, specification-driven
behavior.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/httpauth"
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func BasicChallenge(realm string) string` | BasicChallenge returns the WWW-Authenticate header value a server sends with a 401 to request HTTP Basic credentials for realm. |
| `func BearerChallenge(realm, errCode string) string` | BearerChallenge returns the WWW-Authenticate header value for a Bearer 401. |
| `func DigestChallenge(p DigestChallengeParams) string` | DigestChallenge renders p as a WWW-Authenticate header value. |
| `func DigestResponse(p DigestParams) (string, error)` | DigestResponse computes the hex "response" value for a Digest credential per RFC 7616 Section 3.4.6. |
| `func EncodeBasic(username, password string) string` | EncodeBasic returns the full "Basic <base64>" Authorization header value for the given username and password, per RFC 7617. |
| `func EncodeBearer(token string) string` | EncodeBearer returns the "Bearer <token>" Authorization header value for token, per RFC 6750. |
| `func HasScheme(header, scheme string) bool` | HasScheme reports whether an Authorization header uses the given scheme, compared case-insensitively. |
| `func ParseBearer(header string) (string, error)` | ParseBearer extracts the token from an "Authorization: Bearer ..." header. |
| `func ParseParams(rest string) map[string]string` | ParseParams parses the comma-separated auth-param list that follows the scheme token in a WWW-Authenticate or Authorization header (e.g. |
| `func ParseScheme(header string) (scheme, rest string, err error)` | ParseScheme splits an Authorization header value into its scheme token and the remaining credentials, without interpreting the credentials. |
| `func QuoteString(s string) string` | QuoteString renders s as an RFC 7230 quoted-string suitable for use as an auth-param value in a WWW-Authenticate header. |
| `func SchemeOf(header string) string` | SchemeOf returns the lower-cased authentication scheme named by an Authorization header value, or "" if the header is empty or malformed. |
| `func SecureCompare(a, b string) bool` | SecureCompare reports whether a and b are equal using a constant-time comparison. |
| `func VerifyDigest(c DigestCredentials, method, password string, body []byte) bool` | VerifyDigest recomputes the expected response digest for c using method (the HTTP request method), password (the user's cleartext password) and body… |

### Types

| Type | What it is |
| --- | --- |
| `BasicCredentials` | BasicCredentials holds a decoded HTTP Basic username and password. |
| `DigestChallengeParams` | DigestChallengeParams describes the WWW-Authenticate challenge a server sends to start a Digest exchange (RFC 7616 Section 3.3). |
| `DigestCredentials` | DigestCredentials is a parsed "Authorization: Digest ..." header. |
| `DigestParams` | DigestParams holds the inputs to an RFC 7616 digest-response computation. |

<details>
<summary><code>BasicCredentials</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseBasic(header string) (BasicCredentials, error)` | ParseBasic decodes an "Authorization: Basic ..." header into its username and password. |
| `func (c BasicCredentials) Matches(username, password string) bool` | Matches reports whether c carries exactly the given username and password, comparing both in constant time so a caller cannot be used as an oracle… |

</details>

<details>
<summary><code>DigestCredentials</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseDigest(header string) (DigestCredentials, error)` | ParseDigest parses a full "Digest ..." Authorization header value. |

</details>

### Constants

`AlgMD5`, `AlgSHA256`, `AlgSHA512_256`, `SchemeBasic`, `SchemeBearer`, `SchemeDigest`

### Variables

`ErrNoHeader`, `ErrWrongScheme`, `ErrMalformed`, `ErrUnknownAlgorithm`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/httpauth).

## Measured parity

Compared case-for-case against **`http-auth-utils@7.0.1`** by the harness in
[`parity/passport/nested/httpauth`](https://github.com/malcolmston/go/tree/main/parity/passport/nested/httpauth):

| | |
| --- | --- |
| Parity | **100%** |
| Cases | 145 |
| Matching | 114 |
| Mismatching | 0 |
| Declared deviations | 31 |

Regenerate from the aggregator repo with `go test ./parity/passport/nested/httpauth/`.
Declared deviations are documented differences, excluded from the denominator
and listed in the harness report.

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
