# patreon — provides a passport OAuth2 strategy preset for Patreon

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/patreon.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/patreon)

Package patreon provides a passport OAuth2 strategy preset for Patreon,
porting the passport-patreon strategy from the Passport.js ecosystem. It is a
thin configuration layer over strategies/oauth2: it fills in Patreon's
authorization, token and identity (userinfo) endpoints so callers only supply
their client credentials, a redirect URL and a verify function.

Use this preset when you want users to sign in with their Patreon account, for
example to gate content behind a membership tier. Because Patreon uses fixed,
global endpoints (unlike tenant-based providers), a single New call with your
OAuth client ID and secret is all that is required.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/patreon"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./patreon/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/patreon">Sign in with Patreon</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Patreon. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/patreon).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
