# token — generates and compares opaque security tokens for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/token.svg)](https://pkg.go.dev/github.com/malcolmston/passport/token)

Package token generates and compares opaque security tokens for the passport
port. Several strategies — bearer tokens, API keys, magic links, "remember
me" cookies — need unpredictable, URL-safe identifiers and a timing-safe way
to check them. Each of those packages currently rolls its own; this package
centralizes the primitives so they share one audited, standard-library-only
implementation.

Generation always draws from crypto/rand and fails closed: any shortfall from
the system entropy source is returned as an error rather than silently
producing a weak token. Comparison uses crypto/subtle for constant-time
equality, avoiding the timing side channels that a plain string compare would
leak. Token lengths are expressed in bytes of entropy; the encoded strings are
longer.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/token"
```

## Usage

This is the package's own `Example`, so it compiles and its output is
asserted on every `go test ./token/`.

```go
issued, err := token.New()
	if err != nil {
		panic(err)
	}

	stored := token.Hash(issued)

	fmt.Println("correct token:", token.Verify(issued, stored))
	fmt.Println("wrong token:", token.Verify("some-other-token", stored))
	fmt.Println("digest length:", len(stored))
```

```
correct token: true
wrong token: false
digest length: 64
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Base32(n int) (string, error)` | Base32 returns a random token of n bytes of entropy encoded as unpadded, upper-case RFC 4648 base32. |
| `func Bytes(n int) ([]byte, error)` | Bytes returns n cryptographically random bytes. |
| `func Equal(a, b string) bool` | Equal reports whether a and b are the same token using a constant-time comparison, so callers do not leak length-independent timing information when… |
| `func EqualBytes(a, b []byte) bool` | EqualBytes reports whether a and b are the same token using a constant-time comparison. |
| `func Hash(token string) string` | Hash returns the SHA-256 digest of a token, hex-encoded. |
| `func Hex(n int) (string, error)` | Hex returns a random token of n bytes of entropy encoded as a lower-case hex string of length 2n. |
| `func MustNew() string` | MustNew returns a URL-safe token like New but panics if the system random source fails. |
| `func New() (string, error)` | New returns a URL-safe token with DefaultEntropyBytes of entropy. |
| `func Numeric(n int) (string, error)` | Numeric returns a random decimal string of exactly n digits, suitable for short verification codes. |
| `func URLSafe(n int) (string, error)` | URLSafe returns a random token of n bytes of entropy encoded with unpadded base64url, safe for use in URLs, cookies, and headers. |
| `func Verify(presented, storedHash string) bool` | Verify reports whether a presented token matches a stored SHA-256 digest as produced by Hash, comparing in constant time. |

### Constants

`DefaultEntropyBytes`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/token).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
