# fortytwo — provides a passport OAuth2 strategy preset for signing users in with their 42 intranet

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/fortytwo.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/fortytwo)

Package fortytwo provides a passport OAuth2 strategy preset for signing users
in with their 42 intranet ("intra") account through api.intra.42.fr. It is the
Go port of the Passport.js passport-42 strategy and a thin wrapper over the
shared strategies/oauth2 engine, presetting 42's authorization and token
endpoints and the v2/me userinfo resource so callers supply only their
application credentials and a verify function.

Use this strategy when you want "Sign in with 42" in a tool for the 42
coding-school network -- student dashboards, project trackers, or community
apps whose users all hold 42 intra accounts. It requests the "public" scope by
default, which returns the user's public profile; request additional scopes
such as "projects" via a custom oauth2.Strategy if you need more.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/fortytwo"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./fortytwo/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/fortytwo">Sign in with 42</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for 42 intra. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/fortytwo).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
