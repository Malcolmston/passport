# querytoken — authenticates requests by reading a token from a URL query parameter (default "token")

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/querytoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/querytoken)

Package querytoken authenticates requests by reading a token from a URL query
parameter (default "token") and validating it with a user-supplied Verify
function. It is the query-string analogue of the header- and cookie-based
token strategies, filling the same niche as passport-http-bearer configured to
read the token from the query string in the Passport.js ecosystem.

Use this strategy for the cases where a credential must ride in the URL rather
than a header: signed download or unsubscribe links, email confirmation links,
webhooks that only support query parameters, WebSocket handshakes, or
third-party callbacks that cannot set an Authorization header. For ordinary
API calls prefer a header-based bearer token, because query strings are more
likely to be logged and leaked.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/querytoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./querytoken/`.

```go
p := passport.New()

	p.Use(querytoken.New(querytoken.Options{
		Param: "token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, querytoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/api/me", p.Authenticate("query-token")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the querytoken Strategy. |
| `Strategy` | Strategy authenticates requests bearing a token in the query string. |
| `VerifyFunc` | VerifyFunc validates a token, returning the authenticated user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a querytoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "query-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/querytoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
