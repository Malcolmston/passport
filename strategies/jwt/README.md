# jwt — JSON Web Token authentication strategy

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/jwt.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwt)

Package jwt implements a JSON Web Token authentication strategy, a Go port of
the Node passport-jwt strategy for the common HMAC-SHA256 (HS256) case. It
verifies a token's signature and standard time claims (exp, nbf) using only
the standard library, then hands the decoded claims to a user-supplied
VerifyFunc that maps them to an application user.

Use this strategy for stateless bearer authentication of APIs, where the
client obtains a signed JWT (from a login endpoint or an identity provider
that shares a symmetric secret with you) and presents it on subsequent
requests. Because the token carries its own claims and is self-verifying, no
server-side session store is required: the same secret that signs a token
verifies it. The Sign helper is provided as a small convenience for issuing
HS256 tokens in tests and simple issuers.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/jwt"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./jwt/`.

```go
const page = `<!doctype html>
<html><body>
<script>
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
fetch("/api/me", { headers: { "Authorization": "Bearer " + token } })
  .then(r => r.text())
  .then(t => console.log(t));
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

### Functions

| Function | What it does |
| --- | --- |
| `func Sign(secret []byte, claims Claims) (string, error)` | Sign creates an HS256 JWT for the given claims and secret. |

### Types

| Type | What it is |
| --- | --- |
| `Claims` | Claims is the decoded JWT payload. |
| `Extractor` | Extractor pulls the compact JWT out of a request, returning "" when the request carries none. |
| `Strategy` | Strategy authenticates requests carrying a signed JWT. |
| `VerifyFunc` | VerifyFunc maps verified token claims to an application user. |

<details>
<summary><code>Claims</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (c Claims) Audience() []string` | Audience returns the "aud" claim as a slice. |
| `func (c Claims) Issuer() string` | Issuer returns the "iss" claim as a string, if present. |
| `func (c Claims) Subject() string` | Subject returns the "sub" claim as a string, if present. |

</details>

<details>
<summary><code>Extractor</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func FromAuthHeaderAsBearerToken() Extractor` | FromAuthHeaderAsBearerToken returns an Extractor that reads the token from the "Authorization: Bearer <jwt>" header. |
| `func FromAuthHeaderWithScheme(scheme string) Extractor` | FromAuthHeaderWithScheme returns an Extractor that reads the token from the Authorization header using an arbitrary scheme name, compared… |
| `func FromBodyField(name string) Extractor` | FromBodyField returns an Extractor that reads the token from a form field, mirroring ExtractJwt.fromBodyField(name). |
| `func FromExtractors(extractors ...Extractor) Extractor` | FromExtractors returns an Extractor that tries each of the given extractors in order and yields the first non-empty token, mirroring… |
| `func FromHeader(name string) Extractor` | FromHeader returns an Extractor that reads the token from a named header, mirroring ExtractJwt.fromHeader(name). |
| `func FromURLQueryParameter(name string) Extractor` | FromURLQueryParameter returns an Extractor that reads the token from a query parameter, mirroring ExtractJwt.fromUrlQueryParameter(name). |

</details>

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(secret []byte, verify VerifyFunc) *Strategy` | New creates a JWT strategy that verifies HS256 tokens with the given secret. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "jwt". |
| `func (s *Strategy) Parse(token string) (Claims, error)` | Parse verifies a token's signature and time claims and returns its claims. |

</details>

### Variables

`ErrMalformed`, `ErrSignature`, `ErrExpired`, `ErrNotYet`, `ErrAlgorithm`, `ErrNoToken`, `ErrIssuer`, `ErrAudience`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/jwt).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
