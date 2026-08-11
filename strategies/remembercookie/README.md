# remembercookie — implements persistent "remember me" login using the selector/validator cookie scheme

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/remembercookie.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/remembercookie)

Package remembercookie implements persistent "remember me" login using the
selector/validator cookie scheme. It ports the intent of Passport.js's
passport-remember-me strategy: it lets a returning visitor be recognized and
logged in automatically from a long-lived cookie, without re-entering their
password, even after their session has expired.

Use this strategy alongside your primary login. When a user checks a "remember
me" box, you generate a fresh token (a random selector plus a random
validator), store the selector together with the validator — or, better, its
digest; see Options.Hash below — keyed to the user, and set a persistent
cookie holding "selector:validator". On a later visit with no active session,
this strategy consults that cookie to re-establish the login. It is
intentionally non-fatal when absent: with no remember cookie the strategy
calls Pass() so the request continues as an anonymous visitor rather than
failing.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/remembercookie"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./remembercookie/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <label>
        <!-- When checked, the server sets the persistent "remember" cookie. -->
        <input type="checkbox" name="remember" value="1"> Remember me
      </label>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func HashValidator(validator string) string` | HashValidator returns the hex-encoded SHA-256 digest of a validator. |

### Types

| Type | What it is |
| --- | --- |
| `LookupFunc` | LookupFunc resolves a selector to the associated user and the stored token value it must be checked against — the validator itself by default, or… |
| `Options` | Options configures the remembercookie Strategy. |
| `Strategy` | Strategy authenticates requests presenting a valid remember-me cookie. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a remembercookie Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "remember-me". |

</details>

### Constants

`CookieName`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/remembercookie).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
