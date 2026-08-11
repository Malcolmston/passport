# oauth1twitter — thin wrapper over strategies/oauth1 that presets Twitter's OAuth 1.0a endpoints

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/oauth1twitter.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth1twitter)

Package oauth1twitter is a thin wrapper over strategies/oauth1 that presets
Twitter's OAuth 1.0a endpoints. It exists so applications can authenticate
with Twitter without repeating the request-token, authorize, and access-token
URLs. It ports passport-twitter's OAuth 1.0a mode: New returns a *oauth1.
Strategy registered under the name "twitter", so it is a provider preset over
the shared OAuth 1.0a base rather than a reimplementation of it.

Use this package when you want "Sign in with Twitter" over the classic OAuth
1.0a (HMAC-SHA1) protocol. Construct a Config with your Twitter application
consumer key and secret plus the CallbackURL you registered in the Twitter
developer portal, pass it to New along with a verify function, and register
the returned strategy with passport under the name "twitter".

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/oauth1twitter"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./oauth1twitter/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/twitter">Sign in with Twitter</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(cfg Config, verify oauth1.VerifyFunc) *oauth1.Strategy` | New builds an oauth1.Strategy named "twitter" wired to Twitter's endpoints. |

### Types

| Type | What it is |
| --- | --- |
| `Config` | Config carries the Twitter application credentials and callback URL. |

### Constants

`RequestTokenURL`, `AuthorizeURL`, `AccessTokenURL`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth1twitter).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
