# cas — client for the CAS (Central Authentication Service) single sign-on protocol

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/cas.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cas)

Package cas implements a client for the CAS (Central Authentication Service)
single sign-on protocol, in the spirit of Passport.js CAS strategies such as
passport-cas / connect-cas. It lets a Go service participate as a CAS client
(service) so that authentication is delegated to a central CAS server shared
across many applications.

Use it in organizations — universities are the canonical example — that
run a CAS server for site-wide single sign-on. A user who has already signed
in to any CAS-protected application is transparently logged in to yours, and
logging out centrally logs them out everywhere.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/cas"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./cas/`.

```go
const page = `<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <a href="/auth/cas">Sign in with CAS</a>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Config` | Config configures the CAS strategy. |
| `Strategy` | Strategy authenticates against a CAS server. |
| `VerifyFunc` | VerifyFunc maps a validated CAS username (and any released attributes) to an application user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(cfg Config, verify VerifyFunc) *Strategy` | New creates a CAS Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) LoginURL() string` | LoginURL is the CAS login redirect target. |
| `func (s *Strategy) Name() string` | Name returns "cas". |
| `func (s *Strategy) Validate(ctx context.Context, ticket string) (string, map[string]string, error)` | Validate calls serviceValidate and returns the authenticated username and any released attributes. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/cas).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
