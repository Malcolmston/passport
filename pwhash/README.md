# pwhash — provides password hashing and verification for the passport port using PBKDF2 (RFC 2898

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/pwhash.svg)](https://pkg.go.dev/github.com/malcolmston/passport/pwhash)
[![Parity](https://img.shields.io/badge/parity-100%25-brightgreen)](https://github.com/malcolmston/go/tree/main/parity/passport/nested/pwhash)

Package pwhash provides password hashing and verification for the passport
port using PBKDF2 (RFC 2898 / PKCS #5) over the standard library only. Local
username/password strategies need a safe way to store and check passwords;
Node's passport ecosystem leans on modules such as passport-local-mongoose for
this, and pwhash supplies the equivalent building block here without any
third-party dependency.

The core Key function is a faithful, allocation-frugal implementation of
PBKDF2 with an HMAC pseudo-random function, verified against the RFC 6070 test
vectors. On top of it, Hash produces a self-describing, Django-style encoded
string — "pbkdf2_<hash>$<iterations>$<b64salt>$<b64dk>" — that captures
every parameter needed to verify it later, and Verify recomputes the derived
key in constant time. Salting uses crypto/rand; Key itself is deterministic.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/pwhash"
```

## Usage

This is the package's own `ExampleHash`, so it compiles and its output is
asserted on every `go test ./pwhash/`.

```go
encoded, err := pwhash.Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	ok, err := pwhash.Verify("correct horse battery staple", encoded)
	fmt.Println("correct password:", ok, err)

	ok, err = pwhash.Verify("hunter2", encoded)
	fmt.Println("wrong password:  ", ok, err)
```

```
correct password: true <nil>
wrong password:   false <nil>
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Hash(password string) (string, error)` | Hash derives a hash of password under the DefaultParams and returns it as a self-describing encoded string that Verify can later check. |
| `func HashWithParams(password string, p Params) (string, error)` | HashWithParams is like Hash but uses the supplied parameters. |
| `func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte` | Key derives a keyLen-byte key from password and salt by applying PBKDF2 with iter iterations of HMAC using the hash constructed by h. |
| `func NeedsRehash(encoded string, want Params) bool` | NeedsRehash reports whether an encoded hash was produced with weaker parameters than want, meaning the stored credential should be re-derived the… |
| `func Verify(password, encoded string) (bool, error)` | Verify reports whether password matches the given encoded hash. |

### Types

| Type | What it is |
| --- | --- |
| `Algorithm` | Algorithm names the HMAC hash underlying a PBKDF2 derivation. |
| `Params` | Params configures how Hash derives and encodes a password hash. |

<details>
<summary><code>Algorithm</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func Decode(encoded string) (alg Algorithm, iterations int, salt, dk []byte, err error)` | Decode parses an encoded pwhash string into its parameters and raw bytes. |

</details>

<details>
<summary><code>Params</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func DefaultParams() Params` | DefaultParams returns recommended parameters: HMAC-SHA256, 600,000 iterations, a 16-byte salt and a 32-byte derived key. |

</details>

### Constants

`MaxIterations`

### Variables

`ErrInvalidHash`, `ErrUnknownAlgorithm`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/pwhash).

## Measured parity

Compared case-for-case against **`pbkdf2@3.1.6`** by the harness in
[`parity/passport/nested/pwhash`](https://github.com/malcolmston/go/tree/main/parity/passport/nested/pwhash):

| | |
| --- | --- |
| Parity | **100%** |
| Cases | 62 |
| Matching | 57 |
| Mismatching | 0 |
| Declared deviations | 5 |

Regenerate from the aggregator repo with `go test ./parity/passport/nested/pwhash/`.
Declared deviations are documented differences, excluded from the denominator
and listed in the harness report.

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
