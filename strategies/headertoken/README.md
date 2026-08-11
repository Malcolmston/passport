# headertoken — authenticates requests by reading an opaque token from an arbitrary

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/headertoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/headertoken)

Package headertoken authenticates requests by reading an opaque token from an
arbitrary, caller-specified request header and validating it with a
user-supplied Verify function. It ports the generic "custom header token" idea
found in the Passport.js ecosystem — strategies such as
passport-http-header-strategy and passport-headerapikey — using only the Go
standard library.

Use this strategy when clients authenticate by presenting a simple bearer
credential (an API key, a session token, a personal access token) in a
dedicated HTTP header rather than in the Authorization header or a form body.
It is the least opinionated of the token strategies: it does not parse, sign,
or interpret the token in any way, leaving all validation semantics to your
Verify function. This makes it a good fit for internal services, machine-to-
machine APIs, and webhook receivers where you control both ends and want to
map a raw string to an application user with minimal ceremony.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/headertoken"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./headertoken/`.

```go
const page = `<!doctype html>
<html><body>
<script>
const token = "s3cr3t-token";
fetch("/api/me", { headers: { "X-Auth-Token": token } })
  .then(r => r.text())
  .then(t => console.log(t));
</script>
</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the headertoken Strategy. |
| `Strategy` | Strategy authenticates requests bearing a token in a custom header. |
| `VerifyFunc` | VerifyFunc validates a token, returning the authenticated user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a headertoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "header-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/headertoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
