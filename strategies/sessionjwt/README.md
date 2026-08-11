# sessionjwt — implements stateless sessions backed by a signed JWT stored in a cookie (default name

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/sessionjwt.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/sessionjwt)

Package sessionjwt implements stateless sessions backed by a signed JWT stored
in a cookie (default name "session"). It is the cookie-carried, self-contained
counterpart to a server-side session store: instead of keeping session state
on the server and referencing it by an opaque ID (as strategies/sessiontoken
does), the session claims themselves travel in an HS256 JWT signed with
strategies/jwt.

Use this strategy when you want login sessions without the operational cost of
a shared session store — the token is self-validating, so any server holding
the signing secret can authenticate a request with no database round-trip.
This suits horizontally scaled or serverless deployments. The trade-off is
that a stateless session cannot be revoked before it expires (short of
rotating the signing secret); if you need per-session revocation, prefer
sessiontoken with a real store, or keep a short TTL here.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/sessionjwt"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./sessionjwt/`.

```go
strategy := sessionjwt.New(sessionjwt.Options{
		Secret: []byte("session-signing-secret"),
	})

	p := passport.New()
	p.Use(strategy)

	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := strategy.Issue(jwt.Claims{"sub": "user-123"}, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		strategy.SetCookie(w, token)
	})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %v", passport.User(r))
	})

	mux := http.NewServeMux()
	mux.Handle("/login", login)

	mux.Handle("/dashboard", p.Authenticate("session-jwt")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy authenticates via a stateless session cookie. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) CookieName() string` | CookieName returns the configured cookie name. |
| `func (s *Strategy) Issue(claims jwt.Claims, ttl time.Duration) (string, error)` | Issue mints a session JWT carrying the given claims, with an exp derived from ttl (a positive ttl overrides any exp already in claims). |
| `func (s *Strategy) Name() string` | Name returns "session-jwt". |
| `func (s *Strategy) SetCookie(w http.ResponseWriter, token string)` | SetCookie writes a session cookie holding token to w. |

</details>

### Constants

`DefaultCookie`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/sessionjwt).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
