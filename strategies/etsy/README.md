# etsy — provides a passport OAuth2 strategy preset for signing users in with their Etsy account

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/etsy.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/etsy)

Package etsy provides a passport OAuth2 strategy preset for signing users in
with their Etsy account through the Etsy Open API v3. It is the Go analogue of
the Passport.js passport-etsy strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting Etsy's www.etsy.com/oauth/connect
authorization endpoint and the api.etsy.com v3 token endpoint so callers
supply only their client credentials and a verify function.

Use this strategy when you want "Sign in with Etsy" or need an access token to
call the Etsy Open API on a seller's or buyer's behalf. No scopes are set by
default; Etsy requires you to request explicit scopes (for example "email_r
shops_r transactions_r"), so for real use register a custom oauth2.Strategy
with the scopes your integration needs.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/etsy"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./etsy/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/etsy">Sign in with Etsy</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Etsy. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/etsy).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
