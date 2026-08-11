# keycloak — provides a passport OAuth2/OIDC strategy preset for Keycloak

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/keycloak.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/keycloak)

Package keycloak provides a passport OAuth2/OIDC strategy preset for Keycloak,
the open-source identity and access management server. It is a thin wrapper
over strategies/oauth2 and ports passport-keycloak-oauth2-oidc: New and
NewWithRealm return a *oauth2.Strategy, so the full OAuth2 base API and its
documented semantics apply here unchanged.

Use this package to authenticate against your own Keycloak deployment. Because
Keycloak is self-hosted and realm-scoped, its OpenID Connect endpoints are
derived from the server host and realm name rather than being fixed. Prefer
NewWithRealm, which builds the endpoints from the host (for example
"keycloak.example.com", without a scheme) and realm you supply; New exists for
convenience and uses placeholder host and realm values that you will almost
always want to override.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/keycloak"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./keycloak/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/keycloak">Sign in with Keycloak</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Keycloak using placeholder host and realm. |
| `func NewWithRealm(host, realm, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithRealm returns an OAuth2 strategy for the given Keycloak host (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/keycloak).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
