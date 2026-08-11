# oauth2 — generic, standard-library-only OAuth 2.0 authorization-code strategy for the passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/oauth2.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth2)

Package oauth2 implements a generic, standard-library-only OAuth 2.0
authorization-code strategy for the passport port. It is the shared engine
behind every concrete OAuth2 provider package in this module (github, google,
kakao, line, microsoft, notion, and the rest): each of those is a thin wrapper
that presets this package's endpoints and default scopes, so the redirect,
token-exchange, and userinfo logic lives here in exactly one place. It ports
passport-oauth2, the Node base strategy that the passport-* provider
strategies extend, and is therefore the core abstraction other providers build
on rather than a standalone provider.

Reach for this package directly when you need to talk to an OAuth2 provider
that has no dedicated wrapper: supply the provider's authorization, token, and
(optionally) userinfo URLs in a Config together with your client credentials
and requested Scopes, and you get a ready passport.Strategy. When a wrapper
does exist, prefer it — it fills in the URLs and sensible default scopes for
you and still returns a *Strategy from this package, so everything documented
here applies unchanged.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/oauth2"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./oauth2/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/oauth2">Sign in</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Config` | Config holds the endpoints and client credentials for an OAuth2 provider. |
| `Profile` | Profile is the normalized identity produced by a successful authentication. |
| `Strategy` | Strategy is a generic OAuth2 authorization-code strategy. |
| `Token` | Token is the parsed response from the token endpoint. |
| `VerifyFunc` | VerifyFunc maps a fetched Profile to an application user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(name string, cfg Config, verify VerifyFunc) *Strategy` | New creates a Strategy registered under name using cfg and verify. |
| `func (s *Strategy) AuthCodeURL(state string) string` | AuthCodeURL builds the provider authorization URL for the given state. |
| `func (s *Strategy) AuthURL() string` | AuthURL returns the provider's configured authorization endpoint. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Exchange(ctx context.Context, code string) (*Token, error)` | Exchange trades an authorization code for a Token at the token endpoint. |
| `func (s *Strategy) FetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error)` | FetchUserInfo GETs the userinfo endpoint using the access token and decodes the JSON body into a generic map. |
| `func (s *Strategy) Name() string` | Name returns the strategy name. |
| `func (s *Strategy) TokenURL() string` | TokenURL returns the provider's configured token endpoint. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/oauth2).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
