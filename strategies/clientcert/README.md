# clientcert — implements TLS client-certificate (mutual TLS) authentication for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/clientcert.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/clientcert)

Package clientcert implements TLS client-certificate (mutual TLS)
authentication for the passport port, comparable to Passport.js's
passport-client-cert. Rather than reading a credential from the request body
or headers, it authenticates the client by the X.509 certificate presented
during the TLS handshake.

Use it for high-assurance service-to-service calls, zero-trust internal
networks, and device or partner integrations where each caller holds a client
certificate issued by a trusted CA. It is stateless and normally mounted with
passport.Options{Session: passport.NoSession()}, since the certificate
re-authenticates every connection.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/clientcert"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./clientcert/`.

```go
const page = `<!doctype html>
<html>
<head><title>Client certificate demo</title></head>
<body>
  <p>Your browser presents a client certificate during the TLS handshake.</p>
  <pre id="out">loading...</pre>
  <script>
    fetch("/secure")
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
| `Options` | Options configures the clientcert Strategy. |
| `Strategy` | Strategy authenticates requests presenting a TLS client certificate. |
| `VerifyFunc` | VerifyFunc maps a verified client certificate to a user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a clientcert Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "client-cert". |

</details>

### Variables

`ErrRejected`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/clientcert).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
