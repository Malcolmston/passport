# dropbox — provides a passport OAuth2 strategy preset for signing users in with their Dropbox

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/dropbox.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/dropbox)

Package dropbox provides a passport OAuth2 strategy preset for signing users
in with their Dropbox account. It is the Go port of the Passport.js
passport-dropbox-oauth2 strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting Dropbox's www.dropbox.com authorization
endpoint, the api.dropboxapi.com token endpoint, and the
users/get_current_account resource so callers supply only their client
credentials and a verify function.

Use this strategy when you want "Sign in with Dropbox" or need an access token
to read or write a user's Dropbox files. No scopes are requested by default;
with scoped Dropbox apps the granted permissions come from your app's
configuration in the Dropbox App Console, or you can request specific scopes
(for example "account_info.read") through a custom oauth2.Strategy.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/dropbox"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./dropbox/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/dropbox">Sign in with Dropbox</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Dropbox. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/dropbox).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
