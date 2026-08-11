# jwks — verifies JSON Web Tokens signed with asymmetric keys (RS256/384/ 512, PS256/384/512

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/jwks.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwks)

Package jwks verifies JSON Web Tokens signed with asymmetric keys (RS256/384/
512, PS256/384/512, ES256/384/512) whose public keys are published as a JWKS
(JSON Web Key Set), as used by OpenID Connect providers such as Google, Auth0,
Okta, Azure AD, and Cognito. It combines the roles of Node's passport-jwt
strategy (bearer-token authentication) and jwks-rsa (fetching and caching a
provider's rotating signing keys) into a single stdlib-only passport.Strategy
whose Name is "jwks". The low-level Verify function additionally supports
HS256/384/512 with a shared secret for symmetric use cases.

Use this strategy to protect an API that accepts provider-issued JWTs — the
typical stateless "Authorization: Bearer <jwt>" pattern for single-page apps,
mobile clients, and service-to-service calls. Rather than sharing a static
secret, the server trusts any token signed by the provider's current private
key and validated against the matching public key from the provider's
published JWKS, so keys can rotate without redeploying your application.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/jwks"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./jwks/`.

```go
const page = `<!doctype html>
<html><body>
  <pre id="out"></pre>
  <script>
    // In production this comes from your OpenID Connect sign-in flow.
    var token = "PROVIDER_ISSUED_JWT";
    fetch("/api/me", {
      headers: {"Authorization": "Bearer " + token}
    }).then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
  </script>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	_ = mux
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Claims` | Claims is a decoded JWT payload. |
| `JWK` | JWK is a single JSON Web Key. |
| `KeyResolver` | KeyResolver returns the verification key for a token's kid and algorithm. |
| `Options` | Options configures a Strategy. |
| `Set` | Set is a JSON Web Key Set. |
| `Strategy` | Strategy authenticates a request carrying a JWT verified against a JWKS. |
| `VerifyFunc` | VerifyFunc maps verified token claims to an application user. |

<details>
<summary><code>Claims</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func Verify(token string, resolve KeyResolver) (Claims, error)` | Verify parses and verifies a JWT using resolve to obtain the key, then checks the exp/nbf time claims. |
| `func (c Claims) Audience() []string` | Audience returns the "aud" claim as a slice (JWT allows string or []string). |
| `func (c Claims) Issuer() string` | Issuer returns the "iss" claim. |
| `func (c Claims) Subject() string` | Subject returns the "sub" claim. |

</details>

<details>
<summary><code>JWK</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (k JWK) PublicKey() (crypto.PublicKey, error)` | PublicKey converts a JWK to a crypto.PublicKey (*rsa.PublicKey or *ecdsa.PublicKey). |

</details>

<details>
<summary><code>Set</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func ParseSet(data []byte) (*Set, error)` | ParseSet parses a JWKS JSON document. |
| `func (s *Set) Key(kid string) (crypto.PublicKey, error)` | Key returns the public key for a kid, or the sole key when kid is empty and the set has exactly one key. |

</details>

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options, verify VerifyFunc) *Strategy` | New creates a JWKS-backed strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "jwks". |
| `func (s *Strategy) VerifyToken(token string) (Claims, error)` | VerifyToken verifies a raw compact JWT using the strategy's configured key source (JWKS endpoint, static Set, or custom resolver) and returns its… |

</details>

### Constants

`DefaultCacheTTL`, `DefaultMaxRefreshesPerMinute`, `DefaultMaxJWKSBytes`, `DefaultFetchTimeout`

### Variables

`ErrMalformed`, `ErrSignature`, `ErrAlgorithm`, `ErrKey`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwks).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
