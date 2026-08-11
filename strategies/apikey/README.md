# apikey — implements shared-secret API-key authentication for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/apikey.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/apikey)

Package apikey implements shared-secret API-key authentication for the
passport port. It is the Go analogue of the community passport-headerapikey
and passport-localapikey strategies for Passport.js: instead of a username and
password, a caller presents a single opaque key that identifies a client or
service, and a user-supplied Verify function resolves that key to an
application user.

Reach for this strategy for machine-to-machine and simple programmatic access
where issuing full OAuth credentials is overkill: internal service calls,
webhooks, cron jobs, or a developer API guarded by keys minted in a dashboard.
It is stateless, so it pairs naturally with passport.Options{Session:
passport.NoSession()} and needs no cookies or redirects.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/apikey"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./apikey/`.

```go
p := passport.New()

	p.Use(apikey.New(apikey.Options{
		Header: "X-API-Key",
		Query:  "api_key",
		Verify: func(key string) (user any, err error) {
			if key == "k3y-abc123" {
				return "service-account", nil
			}
			return nil, apikey.ErrInvalidKey
		},
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/private", p.Authenticate("apikey", passport.Options{Session: passport.NoSession()})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the apikey Strategy. |
| `Strategy` | Strategy authenticates requests presenting a shared API key. |
| `VerifyFunc` | VerifyFunc validates an API key, returning the authenticated user on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates an apikey Strategy from the given options. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "apikey". |

</details>

### Variables

`ErrInvalidKey`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/apikey).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
