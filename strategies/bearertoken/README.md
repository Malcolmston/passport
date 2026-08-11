# bearertoken — implements opaque bearer-token authentication via token introspection for the passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/bearertoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bearertoken)

Package bearertoken implements opaque bearer-token authentication via token
introspection for the passport port. It is a focused variant of the
passport-http-bearer idea: the token is read only from the standard
"Authorization: Bearer <token>" header and handed to a user-supplied
VerifyFunc that introspects it — against a local token store, a cache, or a
remote RFC 7662 introspection endpoint.

Reach for this strategy when tokens are validated by asking an authority
whether they are still active, rather than by verifying a self-contained
signature (for which a JWT strategy is more appropriate). It suits API
gateways and resource servers in an OAuth2 deployment; like the other token
strategies it is stateless and typically mounted with
passport.Options{Session: passport.NoSession()}.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/bearertoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./bearertoken/`.

```go
p := passport.New()

	p.Use(bearertoken.New(func(token string) (user any, err error) {
		if token == "t0k3n-abc123" {
			return "service-account", nil
		}
		return nil, bearertoken.ErrInvalidToken
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/private", p.Authenticate("bearer-token", passport.Options{Session: passport.NoSession()})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates requests bearing an opaque access token. |
| `VerifyFunc` | VerifyFunc introspects an opaque token, returning the authenticated user on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a bearertoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "bearer-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bearertoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
