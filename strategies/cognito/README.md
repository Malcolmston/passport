# cognito — provides a passport OAuth2/OIDC strategy preset for signing users in through an Amazon

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/cognito.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cognito)

Package cognito provides a passport OAuth2/OIDC strategy preset for signing
users in through an Amazon Cognito user pool's hosted UI. It corresponds to
the passport-oauth2 / passport-amazon-cognito-oauth2 strategies used with
Passport.js and is a thin wrapper over the shared strategies/oauth2 engine.
Because every Cognito user pool is served from its own domain, the endpoints
cannot be hard-coded: New uses a placeholder domain for quick experiments,
while NewWithDomain targets your real hosted-UI domain.

Reach for this strategy when your identities live in Cognito -- for example an
AWS-centric application that federates Google, Apple, SAML, or username and
password logins behind a single user pool. The default scopes are the OIDC set
"openid", "email", and "profile", which return a stable subject (sub) plus the
user's email and basic profile claims from the pool's /oauth2/userInfo
endpoint.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/cognito"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./cognito/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/cognito">Sign in with Amazon Cognito</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Cognito using the placeholder domain. |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Cognito hosted-UI domain (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cognito).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
