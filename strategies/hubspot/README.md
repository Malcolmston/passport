# hubspot — provides a passport authentication strategy for signing users in with their HubSpot

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/hubspot.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hubspot)

Package hubspot provides a passport authentication strategy for signing users
in with their HubSpot account over OAuth 2.0. It is a thin preset around the
shared strategies/oauth2 engine, wiring in HubSpot's authorization and token
endpoints so callers only supply their client credentials, a redirect URL, and
a verify function. It ports the Node passport-hubspot strategy to this
standard-library-only module.

Reach for this package when your application connects to a user's HubSpot
account — for example an integration that reads or writes CRM data on their
behalf — using the familiar Passport-style
register-a-strategy-then-mount-two- routes flow. Because it delegates to
strategies/oauth2, the Profile shape, the VerifyFunc contract, and the
redirect/callback handling all apply here unchanged; this package's only job
is to fill in the HubSpot-specific configuration.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/hubspot"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./hubspot/`.

```go
const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/hubspot">Sign in with HubSpot</a>
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
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for HubSpot. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hubspot).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
