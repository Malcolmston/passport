# facebook — provides a passport OAuth2 strategy preset for signing users in with their Facebook

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/facebook.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/facebook)

Package facebook provides a passport OAuth2 strategy preset for signing users
in with their Facebook account. It is the Go port of the widely used
Passport.js passport-facebook strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting Facebook's Login dialog, the Graph API
token endpoint, and the /me userinfo resource so callers supply only their app
credentials and a verify function.

Use this strategy when you want a "Sign in with Facebook" (Facebook Login)
flow in a consumer web application. It requests the "email" scope (permission)
by default and asks the Graph API for the id, name, and email fields; request
additional permissions such as "public_profile" or "user_friends" through a
custom oauth2.Strategy, remembering that most permissions require Facebook App
Review before they work for the public.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/facebook"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./facebook/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/facebook">Sign in with Facebook</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Facebook. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/facebook).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
