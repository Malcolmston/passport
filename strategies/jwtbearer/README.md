# jwtbearer — implements the JWT Bearer authorization grant of RFC 7523 ("JSON Web Token (JWT)

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/jwtbearer.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwtbearer)

Package jwtbearer implements the JWT Bearer authorization grant of RFC 7523
("JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
Authorization Grants") for the passport port. It is the standard-library
counterpart to the Node passport-oauth2-jwt-bearer and @node-oauth JWT bearer
implementations, letting a client authenticate by presenting a signed JWT
assertion instead of a username and password.

Use this strategy on a token or resource endpoint that must accept RFC 7523
bearer assertions: server-to-server flows where one service proves its
identity with a JWT signed by its own key, and federated scenarios where an
external identity provider issues assertions that your service accepts. It
fits an OAuth 2.0 token endpoint receiving grant_type
urn:ietf:params:oauth:grant-type:jwt-bearer (exported as GrantType), and it is
the natural choice when credentials are asymmetric keys published as a JWKS
rather than shared secrets.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/jwtbearer"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./jwtbearer/`.

```go
p := passport.New()

	p.Use(jwtbearer.New(jwtbearer.Options{
		Secret: []byte("shared-assertion-secret"),
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "granted: %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/oauth/token", p.Authenticate("jwt-bearer")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy authenticates requests presenting a JWT bearer assertion. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "jwt-bearer". |

</details>

### Constants

`GrantType`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwtbearer).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
