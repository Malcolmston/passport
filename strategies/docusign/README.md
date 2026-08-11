# docusign — provides a passport OAuth2 strategy preset for signing users in with their DocuSign

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/docusign.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/docusign)

Package docusign provides a passport OAuth2 strategy preset for signing users
in with their DocuSign account. It is the Go port of the Passport.js
passport-docusign strategy and a thin wrapper over the shared
strategies/oauth2 engine, presetting DocuSign's production
account.docusign.com authorization, token, and userinfo endpoints so callers
supply only their client credentials and a verify function.

Use this strategy when you want "Sign in with DocuSign" or need an access
token to call the DocuSign eSignature REST API on the user's behalf. It
requests the "signature" scope by default, which is required to send and
manage envelopes; add scopes such as "extended" (for a refresh token) or
"impersonation" via a custom oauth2.Strategy when you need them.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/docusign"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./docusign/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Log in</title>
<a href="/auth/docusign">Sign in with DocuSign</a>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for DocuSign. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/docusign).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
