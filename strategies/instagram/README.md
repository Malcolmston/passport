# instagram — provides a passport authentication strategy for signing users in with their Instagram

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/instagram.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/instagram)

Package instagram provides a passport authentication strategy for signing
users in with their Instagram account over OAuth 2.0. It is a thin preset
around the shared strategies/oauth2 engine, wiring in Instagram's
authorization, token, and userinfo endpoints so callers only supply their
client credentials, a redirect URL, and a verify function. It ports the Node
passport-instagram strategy to this standard-library-only module.

Reach for this package when your application authenticates people through
their Instagram account — for example to read their basic profile via the
Instagram Basic Display / Graph API — using the familiar Passport-style
register-a- strategy-then-mount-two-routes flow. Because it delegates to
strategies/oauth2, the Profile shape, the VerifyFunc contract, and the
redirect/callback handling all apply here unchanged; this package's only job
is to fill in the Instagram-specific configuration.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/instagram"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./instagram/`.

```go
const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/instagram">Sign in with Instagram</a>
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
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Instagram. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/instagram).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
