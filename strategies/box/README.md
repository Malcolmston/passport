# box — provides an OAuth2 "Sign in with Box" authentication strategy for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/box.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/box)

Package box provides an OAuth2 "Sign in with Box" authentication strategy for
the passport port. It is the Go equivalent of the passport-box strategy for
Passport.js and authenticates users against Box's public OAuth2 endpoints. The
package is a thin preset over the shared strategies/oauth2 engine, presetting
Box's authorization endpoint (https://account.box.com/api/oauth2/authorize),
token endpoint (https://api.box.com/oauth2/token) and current-user endpoint
(https://api.box.com/2.0/users/me).

Use this strategy when you want visitors to sign in with their existing Box
account instead of a local username and password. It suits content and
file-management integrations that act on behalf of Box users. Because it is a
preset over the generic OAuth2 strategy, everything the base engine supports
(a custom HTTP client, state handling and the verify contract) is available
here too.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/box"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./box/`.

```go
const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/box">Sign in with Box</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Box. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/box).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
