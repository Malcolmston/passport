# stackexchange — provides a Passport strategy preset for signing users in with Stack Exchange using

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/stackexchange.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/stackexchange)

Package stackexchange provides a Passport strategy preset for signing users in
with Stack Exchange using OAuth 2.0. It is the Go port of the
passport-stack-exchange strategy from the Passport.js ecosystem, and is a thin
configuration wrapper over strategies/oauth2 that hard-codes Stack Exchange's
authorization and token endpoints so that callers only supply their client
credentials and a verify callback.

Reach for this package when you want a "Sign in with Stack Exchange" button in
a net/http server without hand-rolling the OAuth 2.0 authorization-code dance.
Stack Exchange is the question-and-answer network that includes Stack
Overflow. Because it delegates to strategies/oauth2, it behaves identically to
every other provider preset in this library, so switching identity providers
is close to a one-line change.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/stackexchange"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./stackexchange/`.

```go
http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in</title>
<a href="/auth/stackexchange">Sign in with Stack Exchange</a>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Stack Exchange. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/stackexchange).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
