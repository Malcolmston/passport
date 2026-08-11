# strava — provides a Passport strategy preset for signing users in with Strava using OAuth 2.0

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/strava.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/strava)

Package strava provides a Passport strategy preset for signing users in with
Strava using OAuth 2.0. It is the Go port of the passport-strava-oauth2
strategy from the Passport.js ecosystem, and is a thin configuration wrapper
over strategies/oauth2 that hard-codes Strava's authorization and token
endpoints so that callers only supply their client credentials and a verify
callback.

Reach for this package when you want a "Sign in with Strava" button in a
net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
Strava is a fitness-tracking network for runners and cyclists. Because it
delegates to strategies/oauth2, it behaves identically to every other provider
preset in this library, so switching identity providers is close to a one-line
change.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/strava"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./strava/`.

```go
http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in</title>
<a href="/auth/strava">Sign in with Strava</a>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Strava. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/strava).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
