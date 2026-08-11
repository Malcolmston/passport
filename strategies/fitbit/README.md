# fitbit — provides a passport OAuth2 strategy preset for signing users in with their Fitbit

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/fitbit.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/fitbit)

Package fitbit provides a passport OAuth2 strategy preset for signing users in
with their Fitbit account. It is the Go port of the Passport.js
passport-fitbit-oauth2 strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting Fitbit's www.fitbit.com authorization
endpoint, the api.fitbit.com token endpoint, and the user profile resource so
callers supply only their client credentials and a verify function.

Use this strategy when you want "Sign in with Fitbit" or need an access token
to read a user's health and activity data (steps, heart rate, sleep, weight)
through the Fitbit Web API. It requests the "profile" scope by default;
request additional scopes such as "activity", "heartrate", or "sleep" through
a custom oauth2.Strategy, since Fitbit gates each data domain behind its own
scope.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/fitbit"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./fitbit/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/fitbit">Sign in with Fitbit</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Fitbit. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/fitbit).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
