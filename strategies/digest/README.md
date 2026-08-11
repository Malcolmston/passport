# digest — SIMPLIFIED form of HTTP Digest access authentication (RFC 7616) using MD5 and qop="auth"

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/digest.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/digest)

Package digest implements a SIMPLIFIED form of HTTP Digest access
authentication (RFC 7616) using MD5 and qop="auth". It is the Go port of the
Passport.js passport-http Digest strategy: rather than transmitting a
password, the client proves knowledge of it by sending a hash computed over a
server-issued nonce, so the cleartext secret never travels on the wire.

Use it when you want browser-native credential prompts without building a
login form or when interoperating with clients (tools, devices, curl --digest)
that speak Digest. Because the browser itself renders the username/password
dialog in response to the challenge, there is no HTML frontend to write; the
"frontend" is simply any request to a protected URL. Digest is stateless per
request, so pair the strategy with passport.Options{Session:
passport.NoSession()}.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/digest"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./digest/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Members area</title>
<!-- Following this link to a Digest-protected resource makes the browser show
     its native username/password dialog; no custom form is needed. -->
<a href="/private">Enter the members area</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the digest Strategy. |
| `Strategy` | Strategy authenticates requests using simplified HTTP Digest. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a digest Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "digest". |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/digest).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
