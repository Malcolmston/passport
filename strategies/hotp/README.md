# hotp — implements HMAC-based One-Time Password (HOTP) authentication as specified in RFC 4226

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/hotp.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hotp)

Package hotp implements HMAC-based One-Time Password (HOTP) authentication as
specified in RFC 4226, packaged as a passport.Strategy whose Name is "hotp".
It is the Go analogue of Node's passport-hotp strategy and provides the
counter-based counterpart to time-based (TOTP) one-time passwords: the same
codes produced by RFC 4226 authenticator apps and hardware tokens.

Use this strategy for a second authentication factor, or a primary one, where
each valid login consumes the next code in a per-user sequence rather than a
code tied to the wall clock. HOTP suits hardware tokens and offline devices
that have no reliable clock but can maintain a monotonically increasing
counter, and it avoids the time-synchronization requirements of TOTP.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/hotp"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./hotp/`.

```go
const page = `<!doctype html>
<html><body>
  <form method="POST" action="/verify">
    <label>User <input type="text" name="user"></label>
    <label>Code <input type="text" name="code" inputmode="numeric"></label>
    <button type="submit">Verify</button>
  </form>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Generate(secret []byte, counter uint64) string` | Generate returns the RFC 4226 HOTP value for the given secret and counter. |

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the hotp Strategy. |
| `Strategy` | Strategy authenticates requests presenting a counter-based one-time password. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates an hotp Strategy, applying defaults for any zero-valued option. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "hotp". |

</details>

### Constants

`Digits`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hotp).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
