# local — implements the username-and-password authentication strategy

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/local.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/local)

Package local implements the username-and-password authentication strategy, a
standard-library-only Go port of passport-local. Credentials are read from the
incoming request and checked by a user-supplied verify function, which is the
single place your application decides whether a login is valid.

Use this strategy for classic form logins where the user submits a username
and password directly to your server, rather than being redirected to a
third-party identity provider. Register it with passport.Use and guard your
login route with passport's Authenticate middleware; on success passport
serializes the returned user into the session so subsequent requests are
authenticated.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/local"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./local/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Log in</title>
<form method="post" action="/login">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates requests with a username and password. |
| `VerifyFunc` | VerifyFunc validates a username/password pair. |
| `VerifyFuncReq` | VerifyFuncReq is like VerifyFunc but also receives the request. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a local Strategy with the default field names. |
| `func NewWithRequest(verify VerifyFuncReq) *Strategy` | NewWithRequest creates a local Strategy whose verify receives the *http.Request (passport-local's passReqToCallback: true). |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns the strategy's registration name, "local". |

</details>

### Variables

`ErrInvalidCredentials`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/local).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
