# onelogin — provides a passport OAuth2/OIDC strategy preset for OneLogin

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/onelogin.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/onelogin)

Package onelogin provides a passport OAuth2/OIDC strategy preset for OneLogin,
porting the passport-onelogin / passport-oauth2 wiring used against OneLogin's
OpenID Connect endpoints. It is a thin configuration layer over
strategies/oauth2: it fills in OneLogin's authorization, token and userinfo
endpoints so callers only supply their client credentials, a redirect URL and
a verify function.

Use this preset when your users authenticate against a OneLogin account using
the standard OAuth 2.0 authorization-code flow. OneLogin is subdomain-based:
each account lives at {subdomain}.onelogin.com, so the endpoints must be built
from that host. New uses a placeholder domain ("example.onelogin.com") so the
zero-configuration call compiles and is discoverable; real deployments must
call NewWithDomain with their actual account host.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/onelogin"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./onelogin/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/onelogin">Sign in with OneLogin</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for OneLogin using the placeholder domain. |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given OneLogin host (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/onelogin).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
