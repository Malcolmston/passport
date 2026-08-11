# openidconnect — OpenID Connect (OIDC) authentication strategy layered on top of the OAuth 2.0

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/openidconnect.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/openidconnect)

Package openidconnect implements an OpenID Connect (OIDC) authentication
strategy layered on top of the OAuth 2.0 authorization-code flow. It ports
passport-openidconnect from the Passport.js ecosystem and, like that module,
is the shared base other OIDC provider presets are built on: Okta, OneLogin,
Azure AD, Auth0, Salesforce and similar providers are just this strategy with
their issuer, endpoints and JWKS URL filled in. Use it directly for any
standards-compliant OIDC provider, or as the foundation for a new
provider-specific preset.

Reach for this strategy (rather than a plain OAuth2 preset) when you need the
identity guarantees OIDC adds on top of OAuth 2.0: a signed id_token whose
claims describe the authenticated end user, validated against a known issuer.
A plain OAuth2 login proves the app obtained an access token; OIDC proves who
the user is by cryptographically verifying the id_token, which is what you
want for single sign-on and account linking.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/openidconnect"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./openidconnect/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OIDC redirect. -->
    <a href="/auth/openidconnect">Sign in with OpenID Connect</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Config` | Config holds the OIDC client configuration. |
| `Strategy` | Strategy is an OpenID Connect authorization-code strategy. |
| `VerifyFunc` | VerifyFunc maps verified id_token claims to an application user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(cfg Config, verify VerifyFunc) *Strategy` | New creates an OIDC Strategy. |
| `func (s *Strategy) AuthCodeURL(state string) string` | AuthCodeURL builds the authorization endpoint URL for the given state. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Exchange(ctx context.Context, code string) (*tokenResponse, error)` | Exchange trades an authorization code for a token response. |
| `func (s *Strategy) Name() string` | Name returns "openidconnect". |

</details>

### Variables

`ErrNoVerificationKey`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/openidconnect).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
