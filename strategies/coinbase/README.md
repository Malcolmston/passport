# coinbase — provides a passport OAuth2 strategy preset for signing users in with their Coinbase

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/coinbase.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/coinbase)

Package coinbase provides a passport OAuth2 strategy preset for signing users
in with their Coinbase account. It is the Go port of the Passport.js
passport-coinbase strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting Coinbase's authorization endpoint
(login.coinbase.com), token endpoint, and the v2/user userinfo resource so
callers supply only their client credentials and a verify function.

Use this strategy when you want a "Sign in with Coinbase" login for a
cryptocurrency or fintech application, or to bootstrap access to a Coinbase
user's wallet data on their behalf. It requests the "wallet:user:read" scope
by default, which grants read access to the authenticated user's public
profile (id, name, avatar). Request additional wallet or transaction scopes by
registering your own oauth2.Strategy if you need more than identity.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/coinbase"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./coinbase/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/coinbase">Sign in with Coinbase</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Coinbase. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/coinbase).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
