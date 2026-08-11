# meetup — provides a passport OAuth2 strategy preset for Meetup, the group-and-event platform

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/meetup.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/meetup)

Package meetup provides a passport OAuth2 strategy preset for Meetup, the
group-and-event platform. It is a thin wrapper over strategies/oauth2 that
presets Meetup's authorization and token endpoints, and it ports
passport-meetup-oauth2. New returns a *oauth2.Strategy, so the full OAuth2
base API and its documented semantics apply here unchanged.

Use this package to let users log in with their Meetup account. Register an
OAuth consumer in the Meetup API settings, then call New with the client (key)
ID, client secret, and the redirect URL you registered, plus a verify function
that maps the result to your application user.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/meetup"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./meetup/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/meetup">Sign in with Meetup</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Meetup. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/meetup).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
