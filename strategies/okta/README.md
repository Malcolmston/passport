# okta — provides a passport OAuth2/OIDC strategy preset for Okta

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/okta.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/okta)

Package okta provides a passport OAuth2/OIDC strategy preset for Okta, porting
the passport-okta-oauth wiring used against Okta in the Passport.js ecosystem.
It is a thin configuration layer over strategies/oauth2: it fills in Okta's
authorization, token and userinfo endpoints so callers only supply their
client credentials, a redirect URL and a verify function.

Use this preset when you want users to sign in with an Okta org (workforce or
customer identity) using the standard OAuth 2.0 authorization-code flow. Okta
is domain-based: every tenant is served from its own host
(your-tenant.okta.com, or a custom domain), so the endpoints must be built
from that host. New uses a placeholder domain ("example.okta.com") purely so
the zero-configuration call compiles and is discoverable; real deployments
must call NewWithDomain with their actual tenant domain.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/okta"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./okta/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/okta">Sign in with Okta</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Okta using the placeholder domain ("example.okta.com"). |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Okta tenant domain (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/okta).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
