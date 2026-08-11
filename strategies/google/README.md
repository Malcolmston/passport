# google — provides a passport OAuth2 authorization-code strategy preset for the Google identity

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/google.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/google)

Package google provides a passport OAuth2 authorization-code strategy preset
for the Google identity provider. It is a thin wrapper around the shared
strategies/oauth2 engine, pre-configured with Google's public authorization,
token and OpenID Connect userinfo endpoints, and it ports the Node
passport-google-oauth20 strategy to Go using only the standard library.

Use this package when you want users to sign in to your application with their
Google account. Call New with your Google Cloud OAuth client credentials and
redirect URL, supply an oauth2.VerifyFunc, and register the resulting
*oauth2.Strategy with passport via Passport.Use. It spares you from wiring
Google's endpoints and scopes onto the generic OAuth2 strategy by hand.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/google"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./google/`.

```go
const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/google">Sign in with Google</a>
  </body>
</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Google. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/google).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
