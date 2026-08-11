# digitalocean — provides a passport OAuth2 strategy preset for signing users in with their DigitalOcean

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/digitalocean.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/digitalocean)

Package digitalocean provides a passport OAuth2 strategy preset for signing
users in with their DigitalOcean account. It is the Go port of the Passport.js
passport-digitalocean strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting DigitalOcean's cloud.digitalocean.com
authorization and token endpoints and the v2/account userinfo resource so
callers supply only their client credentials and a verify function.

Use this strategy when you want "Sign in with DigitalOcean" in a developer
tool, deployment dashboard, or any product that integrates with a user's
DigitalOcean account. It requests the "read" scope by default, which grants
read-only access to the account's profile; request "read write" via a custom
oauth2.Strategy if your application manages the user's resources.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/digitalocean"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./digitalocean/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/digitalocean">Sign in with DigitalOcean</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for DigitalOcean. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/digitalocean).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
