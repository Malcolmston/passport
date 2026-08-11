# basicverify — implements HTTP Basic authentication (RFC 7617) with a user-supplied verify function

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/basicverify.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/basicverify)

Package basicverify implements HTTP Basic authentication (RFC 7617) with a
user-supplied verify function and a configurable realm. It is a self-contained
sibling of strategies/basic and the same conceptual port of the BasicStrategy
from Passport.js's passport-http, packaged with an Options struct so the realm
can be set explicitly.

Use it where you want Basic auth but need control over the realm reported to
clients — for example to present a specific application name in the
browser's credential prompt, or to distinguish protected areas. Like Basic
auth generally it should run over HTTPS and is usually mounted statelessly
with passport.Options{Session: passport.NoSession()}.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/basicverify"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./basicverify/`.

```go
const page = `<!doctype html>
<html>
<head><title>Basic verify demo</title></head>
<body>
  <pre id="out">loading...</pre>
  <script>
    fetch("/private", { headers: { "Authorization": "Basic " + btoa("alice:s3cret") } })
      .then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
  </script>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the basicverify Strategy. |
| `Strategy` | Strategy authenticates requests using HTTP Basic credentials. |
| `VerifyFunc` | VerifyFunc validates a username/password pair, returning the authenticated user on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a basicverify Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "basic-verify". |

</details>

### Variables

`ErrInvalidCredentials`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/basicverify).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
