# discord — provides a passport OAuth2 strategy preset for signing users in with their Discord

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/discord.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/discord)

Package discord provides a passport OAuth2 strategy preset for signing users
in with their Discord account. It is the Go port of the Passport.js
passport-discord strategy: a thin wrapper over the shared strategies/oauth2
engine that presets Discord's authorization, token, and userinfo endpoints
(the discord.com/api/oauth2 endpoints and the users/@me resource) so callers
only supply their client credentials and a verify function.

Use this strategy when you want "Sign in with Discord" in a web application:
user identification, community or bot dashboards, or any product whose
audience already has Discord accounts. It requests the "identify" and "email"
scopes by default, which return the user's id, username, avatar, and verified
email. If you need guilds, connections, or other data, register your own
oauth2.Strategy with wider scopes instead.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/discord"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./discord/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/discord">Sign in with Discord</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Discord. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/discord).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
