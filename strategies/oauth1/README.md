# oauth1 — implements the core of an OAuth 1.0a (RFC 5849) authentication strategy using HMAC-SHA1

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/oauth1.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth1)

Package oauth1 implements the core of an OAuth 1.0a (RFC 5849) authentication
strategy using HMAC-SHA1 signatures, built on the standard library only. It is
the shared base that provider wrappers such as strategies/oauth1twitter build
on: those packages preset the request-token, authorize, and access-token
endpoints and delegate the entire signing and HTTP dance to this package. It
ports passport-oauth1, the Node base strategy behind the OAuth 1.0a provider
strategies (Twitter and friends), and so it is the core abstraction rather
than a standalone provider.

Use this package directly when you must authenticate against an OAuth 1.0a
provider that has no dedicated wrapper — anything still speaking the
pre-OAuth2 three-legged protocol with HMAC-SHA1 request signing. Supply the
three provider endpoints and your consumer key/secret in a Config and you get
a ready passport.Strategy. When a wrapper exists (oauth1twitter), prefer it:
it returns a *Strategy from this package, so everything documented here
applies.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/oauth1"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./oauth1/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/oauth1">Sign in</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Sign(method, rawURL string, params map[string]string, consumerSecret, tokenSecret string) string` | Sign computes the OAuth 1.0a HMAC-SHA1 oauth_signature (base64-encoded) for a request. |

### Types

| Type | What it is |
| --- | --- |
| `Config` | Config holds the client credentials and endpoints for an OAuth 1.0a provider. |
| `Strategy` | Strategy is a generic OAuth 1.0a (HMAC-SHA1) authorization strategy. |
| `VerifyFunc` | VerifyFunc maps a granted access token (and the raw token-endpoint response parameters) to an application user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(name string, cfg Config, verify VerifyFunc) *Strategy` | New creates a Strategy registered under name. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns the strategy name. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth1).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
