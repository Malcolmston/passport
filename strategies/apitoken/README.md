# apitoken — implements opaque API-token authentication for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/apitoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/apitoken)

Package apitoken implements opaque API-token authentication for the passport
port. It is a bearer-style companion to strategies/apikey and covers similar
ground to token variants of passport-http-bearer: a client presents a token
and a caller-supplied store resolves it to a user, but here the token travels
in the Authorization header rather than an X-API-Key header.

Use this strategy for stateless service and programmatic access when your
tokens are presented the way OAuth bearer tokens are — "Authorization:
Bearer <token>" — but are opaque secrets you issue and validate yourself
rather than signed JWTs. Like the other token strategies it establishes no
session and is typically mounted with passport.Options{Session:
passport.NoSession()}.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/apitoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./apitoken/`.

```go
p := passport.New()

	p.Use(apitoken.New(apitoken.Options{
		Header: "X-API-Token",
		Lookup: func(token string) (user any, ok bool) {
			if apitoken.ConstantTimeEqual(token, "t0k3n-abc123") {
				return "service-account", true
			}
			return nil, false
		},
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/private", p.Authenticate("api-token", passport.Options{Session: passport.NoSession()})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func ConstantTimeEqual(a, b string) bool` | ConstantTimeEqual reports whether a and b are equal using a constant-time comparison, safe against timing attacks. |

### Types

| Type | What it is |
| --- | --- |
| `LookupFunc` | LookupFunc resolves a presented token to a user. |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy authenticates requests presenting an API token. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "api-token". |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/apitoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
