# reddit — provides a passport OAuth2 strategy preset for the Reddit identity provider

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/reddit.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/reddit)

Package reddit provides a passport OAuth2 strategy preset for the Reddit
identity provider, porting the passport-reddit strategy from the Passport.js
ecosystem. It is a thin configuration layer over strategies/oauth2: it fills
in Reddit's public authorization, token and userinfo endpoints so callers only
supply their client credentials, a redirect URL and a verify function.

Use this preset when you want users to sign in with their Reddit account.
Reddit uses fixed, global endpoints, so a single New call with your OAuth app
ID and secret is all that is required.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/reddit"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./reddit/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/reddit">Sign in with Reddit</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Reddit. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/reddit).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
