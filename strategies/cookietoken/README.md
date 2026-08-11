# cookietoken — authenticates requests by reading an opaque token from a named HTTP cookie

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/cookietoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cookietoken)

Package cookietoken authenticates requests by reading an opaque token from a
named HTTP cookie and validating it with a user-supplied VerifyFunc. It is a
token-extraction strategy rather than a redirect or credential-prompt flow:
the browser is expected to already hold a token (issued by your login
endpoint) in a cookie, and this strategy turns that token into an
authenticated user on each request.

Reach for it when a token lives in a cookie rather than in an Authorization
header -- for example a same-site web app that stores a session or API token
client-side, or a setup where a reverse proxy or login service drops a signed
token cookie that your backend must validate. It is the cookie-based
counterpart to a bearer-token strategy.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/cookietoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./cookietoken/`.

```go
p := passport.New()

	p.Use(cookietoken.New(cookietoken.Options{
		Cookie: "token",
		Verify: func(token string) (user any, err error) {
			if token != "s3cr3t-token" {
				return nil, cookietoken.ErrInvalidToken
			}
			return "user-42", nil
		},
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/api/me", p.Authenticate("cookie-token")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the cookietoken Strategy. |
| `Strategy` | Strategy authenticates requests bearing a token in a cookie. |
| `VerifyFunc` | VerifyFunc validates a token, returning the authenticated user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a cookietoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "cookie-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cookietoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
