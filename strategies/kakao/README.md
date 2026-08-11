# kakao — provides a passport OAuth2 strategy preset for Kakao

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/kakao.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/kakao)

Package kakao provides a passport OAuth2 strategy preset for Kakao, the Korean
"Sign in with Kakao" identity provider. It is a thin wrapper over
strategies/oauth2 that presets Kakao's authorization, token, and userinfo
endpoints, and it ports passport-kakao from the Node ecosystem. New returns a
*oauth2.Strategy, so the full OAuth2 base API and its documented semantics
apply here unchanged.

Use this package to let users log in with their Kakao account. Register a
Kakao application in the Kakao Developers console, then call New with the
application's REST API key as the client ID, its client secret, and the
redirect URL you registered, plus a verify function that maps the returned
profile to your application user.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/kakao"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./kakao/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/kakao">Sign in with Kakao</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Kakao. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/kakao).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
