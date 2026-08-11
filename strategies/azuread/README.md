# azuread — provides an OAuth2/OIDC "Sign in with Microsoft" authentication strategy

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/azuread.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/azuread)

Package azuread provides an OAuth2/OIDC "Sign in with Microsoft"
authentication strategy for the passport port, targeting Azure AD (the
Microsoft identity platform v2.0). It is the Go analogue of the
passport-azure-ad family of strategies for Passport.js. The package is a
preset over the shared strategies/oauth2 engine: the authorization and token
endpoints are built under
https://login.microsoftonline.com/<tenant>/oauth2/v2.0, and the profile is
read from the Microsoft Graph OIDC userinfo endpoint
(https://graph.microsoft.com/oidc/userinfo).

Use this strategy to let users sign in with a Microsoft work, school or
personal account. New targets the multi-tenant "common" endpoint, which
accepts any Azure AD or personal Microsoft account; call NewWithTenant to
restrict login to a specific tenant (a tenant id or domain) or to the
"organizations" or "consumers" audiences.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/azuread"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./azuread/`.

```go
const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/azuread">Sign in with Microsoft</a>
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
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Azure AD using the "common" endpoint. |
| `func NewWithTenant(tenant, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithTenant returns an OAuth2 strategy for the given Azure AD tenant (a tenant ID/domain, or "common", "organizations", "consumers"). |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/azuread).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
