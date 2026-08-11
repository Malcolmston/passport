# refreshtoken — authenticates OAuth2-style refresh-token requests

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/refreshtoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/refreshtoken)

Package refreshtoken authenticates OAuth2-style refresh-token requests, the
grant a client uses at a token endpoint to trade a long-lived refresh_token
for a fresh access token. It mirrors the server side of the OAuth 2.0
"refresh_token" grant (RFC 6749 section 6) rather than any single Passport.js
module, and complements strategies/refreshjwt: use this one when refresh
tokens are opaque strings tracked in your own store, and refreshjwt when they
are self-contained signed JWTs.

Use this strategy on the /oauth/token (or equivalent) endpoint of an
authorization server or API. The client POSTs its refresh token there when its
access token expires; the strategy extracts and validates the token, and on
success the handler mints and returns a new access token (and optionally a
rotated refresh token). Because validation goes through a user-supplied Verify
function backed by your store, you can implement revocation, expiry, rotation
and reuse detection there — capabilities a stateless JWT cannot offer.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/refreshtoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./refreshtoken/`.

```go
p := passport.New()

	p.Use(refreshtoken.New(func(token string) (user any, err error) {
		if token != "stored-refresh-token" {
			return nil, refreshtoken.ErrInvalidToken
		}
		return "user-123", nil
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "new access token for %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/oauth/token", p.Authenticate("refresh-token")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates requests presenting a refresh token in their body. |
| `VerifyFunc` | VerifyFunc validates a refresh token, returning the authenticated user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a refreshtoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "refresh-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/refreshtoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
