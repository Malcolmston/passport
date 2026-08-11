# deezer — provides a passport OAuth2 strategy preset for signing users in with their Deezer

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/deezer.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/deezer)

Package deezer provides a passport OAuth2 strategy preset for signing users in
with their Deezer account. It is the Go port of the Passport.js
passport-deezer strategy and a thin wrapper over the shared strategies/oauth2
engine, presetting Deezer's connect.deezer.com authorization and token
endpoints so callers supply only their client credentials and a verify
function.

Use this strategy when you want a "Sign in with Deezer" login for a music
application. It requests the "basic_access" scope by default, which grants the
user's public profile; add scopes such as "email" or "manage_library" by
registering your own oauth2.Strategy if you need them.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/deezer"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./deezer/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/deezer">Sign in with Deezer</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Deezer. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/deezer).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
