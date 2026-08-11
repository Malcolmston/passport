# auth0 — provides an OAuth2/OIDC "Sign in with Auth0" authentication strategy for the passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/auth0.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/auth0)

Package auth0 provides an OAuth2/OIDC "Sign in with Auth0" authentication
strategy for the passport port. It is the Go equivalent of the passport-auth0
strategy for Passport.js and authenticates users against an Auth0 tenant's
hosted login. The package is a preset over the shared strategies/oauth2
engine: because every Auth0 tenant is served from its own host, the
authorization (/authorize), token (/oauth/token) and userinfo (/userinfo)
endpoints are derived from a tenant domain rather than hard-coded.

Use this strategy when your identity provider is Auth0 and you want to
delegate login (including Auth0's social connections, database users and
enterprise SSO) to the Auth0 Universal Login page. New targets a placeholder
domain ("YOUR_DOMAIN.auth0.com") and exists mainly so the package satisfies
the common New(...) shape; real deployments must call NewWithDomain to point
the strategy at their actual tenant domain (for example
"your-tenant.us.auth0.com").

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/auth0"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./auth0/`.

```go
const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/auth0">Sign in with Auth0</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Auth0 using the placeholder domain ("YOUR_DOMAIN.auth0.com"). |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Auth0 tenant domain (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/auth0).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
