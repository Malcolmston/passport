# salesforce — provides a passport OAuth2/OIDC strategy preset for Salesforce

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/salesforce.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/salesforce)

Package salesforce provides a passport OAuth2/OIDC strategy preset for
Salesforce, porting the passport-salesforce (Force.com / OpenID Connect)
wiring from the Passport.js ecosystem. It is a thin configuration layer over
strategies/oauth2: it fills in Salesforce's authorization, token and userinfo
endpoints so callers only supply their connected-app credentials, a redirect
URL and a verify function.

Use this preset when you want users to sign in with their Salesforce org.
Salesforce authenticates against a login host: login.salesforce.com for
production orgs, test.salesforce.com for sandboxes, and a My Domain host
(your-domain.my.salesforce.com) for orgs with My Domain enabled. New targets
the production login host; call NewWithDomain to point at a sandbox or My
Domain host.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/salesforce"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./salesforce/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/salesforce">Sign in with Salesforce</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Salesforce using the production login host ("login.salesforce.com"). |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Salesforce login host (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/salesforce).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
