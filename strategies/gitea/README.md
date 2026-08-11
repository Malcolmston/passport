# gitea — provides a passport OAuth2 authorization-code strategy preset for the Gitea identity

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/gitea.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/gitea)

Package gitea provides a passport OAuth2 authorization-code strategy preset
for the Gitea identity provider. It is a thin wrapper around the shared
strategies/oauth2 engine, pre-configured with Gitea's authorization, token and
userinfo endpoint paths, and it ports the community Node passport-gitea
strategy to Go using only the standard library.

Use this package when you want users to sign in to your application with an
account on a Gitea server. Because Gitea is self-hosted, its endpoints are
derived from the instance host: NewWithDomain builds the AuthURL, TokenURL and
UserInfoURL from a host such as "gitea.example.com". Call NewWithDomain (or
New) with your OAuth2 application credentials and redirect URL, supply an
oauth2.VerifyFunc, and register the resulting *oauth2.Strategy with passport
via Passport.Use. New exists mainly for symmetry with the other presets: it
uses the placeholder host "gitea.example.com" (the defaultHost constant),
which is almost never what you want, so prefer NewWithDomain to point at your
real instance.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/gitea"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./gitea/`.

```go
const page = `<!doctype html>
<html>
  <body>
    <a href="/auth/gitea">Sign in with Gitea</a>
  </body>
</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Gitea using the placeholder host. |
| `func NewWithDomain(host, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Gitea host (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/gitea).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
