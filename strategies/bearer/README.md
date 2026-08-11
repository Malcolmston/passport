# bearer — implements HTTP Bearer token authentication (RFC 6750) for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/bearer.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bearer)

Package bearer implements HTTP Bearer token authentication (RFC 6750) for the
passport port. It is a Go port of passport-http-bearer: a client presents an
opaque access token and a user-supplied VerifyFunc resolves it to an
application user. It is the classic way to protect an OAuth2-style API where
tokens are issued elsewhere and merely validated here.

Use it to guard API endpoints consumed by single-page apps, mobile clients or
other services that hold an access token. It creates no session and is
normally mounted with passport.Options{Session: passport.NoSession()}; the
token, not a cookie, authenticates every request.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/bearer"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./bearer/`.

```go
p := passport.New()

	p.Use(bearer.New(func(token string) (user any, err error) {
		if token == "t0k3n-abc123" {
			return "service-account", nil
		}
		return nil, bearer.ErrInvalidToken
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/private", p.Authenticate("bearer", passport.Options{Session: passport.NoSession()})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates requests bearing an opaque access token. |
| `VerifyFunc` | VerifyFunc validates a bearer token, returning the authenticated user on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a bearer Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "bearer". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bearer).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
