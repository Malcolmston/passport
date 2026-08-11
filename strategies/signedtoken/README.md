# signedtoken — implements self-contained, stateless bearer-token authentication using

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/signedtoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/signedtoken)

Package signedtoken implements self-contained, stateless bearer-token
authentication using HMAC-SHA256-signed JSON claims. A token carries its own
claims object signed with a shared secret, so any process holding that secret
can verify it without a database lookup or session store. It fills the same
niche as the token strategies in the Passport.js ecosystem
(passport-http-bearer and JWT-style strategies), but with a deliberately
minimal, dependency-free token format rather than full JWT/JOSE.

Reach for this package for machine-to-machine and API authentication, where a
caller presents a token on every request instead of maintaining a cookie
session. It is a natural fit for single-page-app and mobile back ends,
internal service-to-service calls, and short-lived signed links. Because
verification is stateless it scales horizontally with no shared session store;
the only shared state required is the HMAC secret. Pair it with
passport.Options{Session: passport.NoSession()} when you want purely stateless
request authentication with no cookie.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/signedtoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./signedtoken/`.

```go
secret := []byte("super-secret-hmac-key")

	token, err := signedtoken.Sign(secret, map[string]any{
		"sub":  "user-42",
		"role": "admin",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = token

	p := passport.New()

	p.Use(signedtoken.New(signedtoken.Options{
		Secret: secret,
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := passport.User(r).(map[string]any)
		fmt.Fprintf(w, "hello %v", claims["sub"])
	})

	mux := http.NewServeMux()

	mux.Handle("/api/me", p.Authenticate("signed-token")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Sign(secret []byte, claims map[string]any) (string, error)` | Sign encodes claims into a signed token using secret. |

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the signedtoken Strategy. |
| `Strategy` | Strategy authenticates requests bearing a self-contained signed token. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a signedtoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "signed-token". |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/signedtoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
