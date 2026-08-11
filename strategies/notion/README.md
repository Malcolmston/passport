# notion — provides a passport OAuth2 strategy preset for Notion, the connected-workspace app

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/notion.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/notion)

Package notion provides a passport OAuth2 strategy preset for Notion, the
connected-workspace app. It is a thin wrapper over strategies/oauth2 that
presets Notion's v1 authorization, token, and users endpoints, and it ports
passport-notion. New returns a *oauth2.Strategy, so the full OAuth2 base API
and its documented semantics apply here unchanged.

Use this package to let users connect or log in with their Notion account,
typically as the first step of an integration that will call the Notion API on
their behalf. Create a public integration in Notion's developer settings, then
call New with the OAuth client ID, client secret, and the redirect URI you
registered, plus a verify function that maps the result to your application
user.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/notion"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./notion/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/notion">Sign in with Notion</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Notion. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/notion).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
