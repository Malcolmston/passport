# otpauth — builds and parses "otpauth://" key URIs for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/otpauth.svg)](https://pkg.go.dev/github.com/malcolmston/passport/otpauth)
[![Parity](https://img.shields.io/badge/parity-100%25-brightgreen)](https://github.com/malcolmston/go/tree/main/parity/passport/nested/otpauth)

Package otpauth builds and parses "otpauth://" key URIs for the passport port.
These URIs are the de-facto interchange format for provisioning time-based
(TOTP) and counter-based (HOTP) one-time-password secrets into authenticator
apps, most commonly by encoding them in a QR code. The passport TOTP and HOTP
strategies verify codes but ship no way to describe an enrollment; this
package provides that missing piece, following the Google Authenticator Key
Uri Format.

A Key captures the OTP type (totp or hotp), the account label and issuer, the
shared secret, and the algorithm/digits parameters. URL renders it to a
canonical otpauth URI and Parse reads one back; the two round-trip. Secrets
are handled as base32 without padding, the encoding authenticator apps expect.
Everything here is deterministic and uses only the standard library, except
GenerateSecret which draws from crypto/rand.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/otpauth"
```

## Usage

This is the package's own `Example`, so it compiles and its output is
asserted on every `go test ./otpauth/`.

```go
key := otpauth.Key{
		Type:    otpauth.TOTP,
		Issuer:  "Example, Inc.",
		Account: "alice@example.com",

		Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	}

	fmt.Println(key.URL())

	at := time.Unix(1_000_000_000, 0)
	code, err := key.Code(at)
	if err != nil {
		panic(err)
	}
	_, ok := key.Verify(code, at, 1)
	fmt.Println("accepted:", ok)
```

```
otpauth://totp/Example,%20Inc.:alice@example.com?algorithm=SHA1&digits=6&issuer=Example%2C%20Inc.&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
accepted: true
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func DecodeSecret(secret string) ([]byte, error)` | DecodeSecret returns the raw bytes of a Key's base32-encoded secret, tolerating lower-case input and missing padding. |
| `func GenerateSecret(n int) (string, error)` | GenerateSecret returns a random base32 secret string (no padding) built from n bytes of entropy. |

### Types

| Type | What it is |
| --- | --- |
| `Key` | Key describes a single OTP credential in the otpauth key-URI model. |
| `Type` | Type is the OTP algorithm family: time-based or counter-based. |

<details>
<summary><code>Key</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func Parse(raw string) (Key, error)` | Parse reads an otpauth URI into a Key, applying the format's defaults (SHA1, 6 digits, 30-second period) for any omitted parameters. |
| `func (k Key) Code(t time.Time) (string, error)` | Code returns the one-time password this Key produces at time t, honoring the Key's Algorithm, Digits, and (for TOTP) Period. |
| `func (k Key) CodeAtCounter(counter uint64) (string, error)` | CodeAtCounter returns the one-time password for an explicit moving factor, bypassing the Key's own Counter and Period. |
| `func (k Key) Label() string` | Label returns the canonical "Issuer:Account" label, or just Account when no issuer is set. |
| `func (k Key) MovingFactor(t time.Time) uint64` | MovingFactor returns the counter that drives the HOTP construction for this Key at time t: k.Counter for an HOTP key (t is ignored), or… |
| `func (k Key) URL() string` | URL renders the Key as a canonical otpauth URI string. |
| `func (k Key) Validate() error` | Validate reports whether k is internally consistent and can produce codes: a known Type and Algorithm, a decodable base32 Secret, a digit count… |
| `func (k Key) Verify(code string, t time.Time, window int) (matched uint64, ok bool)` | Verify reports whether code is valid for this Key at time t, accepting any code within window moving-factor steps of the expected one, and returns… |

</details>

### Variables

`ErrUnknownAlgorithm`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/otpauth).

## Measured parity

Compared case-for-case against **`otpauth@9.5.1`** by the harness in
[`parity/passport/nested/otpauth`](https://github.com/malcolmston/go/tree/main/parity/passport/nested/otpauth):

| | |
| --- | --- |
| Parity | **100%** |
| Cases | 107 |
| Matching | 99 |
| Mismatching | 0 |
| Declared deviations | 8 |

Regenerate from the aggregator repo with `go test ./parity/passport/nested/otpauth/`.
Declared deviations are documented differences, excluded from the denominator
and listed in the harness report.

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
