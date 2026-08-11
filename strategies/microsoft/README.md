# microsoft — provides a passport OAuth2/OIDC strategy preset for the Microsoft identity platform

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/microsoft.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/microsoft)

Package microsoft provides a passport OAuth2/OIDC strategy preset for the
Microsoft identity platform (Azure AD / Entra ID), which backs "Sign in with
Microsoft" for both work/school and personal accounts. It is a thin wrapper
over strategies/oauth2 that presets the v2.0 authorization, token, and Graph
profile endpoints, and it ports passport-microsoft. New returns a
*oauth2.Strategy, so the full OAuth2 base API and its documented semantics
apply here unchanged.

Use this package to let users log in with a Microsoft account. Register an
application in the Azure portal (Entra ID app registrations), then call New
with the application (client) ID, a client secret, and the redirect URI you
registered, plus a verify function that maps the returned profile to your
application user.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/microsoft"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./microsoft/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/microsoft">Sign in with Microsoft</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Microsoft. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/microsoft).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
