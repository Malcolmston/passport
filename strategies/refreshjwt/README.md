# refreshjwt — authenticates a request using a refresh-token JWT carried in a cookie (default name

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/refreshjwt.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/refreshjwt)

Package refreshjwt authenticates a request using a refresh-token JWT carried
in a cookie (default name "refresh_token"). It fills the same role as the
refresh-token half of the JWT-based session patterns in the Passport.js
ecosystem: a long-lived, signed credential that lets a client obtain fresh
short-lived access tokens without re-entering their password.

Use this strategy for the token-refresh endpoint of an API. A typical setup
issues a short-lived access token (checked by strategies/jwt or bearer) plus a
long-lived refresh JWT stored in an HttpOnly cookie; when the access token
expires, the client calls the refresh endpoint, this strategy validates the
refresh cookie, and the handler mints a new access token. Keeping the refresh
token in a self-contained JWT means the server does not need a database lookup
to validate it, at the cost of not being able to revoke an individual token
before it expires.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/refreshjwt"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./refreshjwt/`.

```go
secret := []byte("refresh-signing-secret")

	strategy := refreshjwt.New(refreshjwt.Options{Secret: secret})

	p := passport.New()
	p.Use(strategy)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "refreshed for %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/auth/refresh", p.Authenticate("refresh-jwt")(protected))

	token, err := strategy.Issue("user-123", 30*24*time.Hour, jwt.Claims{"scope": "api"})
	if err != nil {
		log.Fatal(err)
	}
	_ = token

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy authenticates via a refresh-token cookie. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Issue(subject string, ttl time.Duration, extra jwt.Claims) (string, error)` | Issue mints a refresh JWT for subject with the given TTL and optional extra claims. |
| `func (s *Strategy) Name() string` | Name returns "refresh-jwt". |

</details>

### Constants

`DefaultCookie`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/refreshjwt).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
