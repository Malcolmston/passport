# basic — implements HTTP Basic authentication (RFC 7617) for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/basic.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/basic)

Package basic implements HTTP Basic authentication (RFC 7617) for the passport
port. It is a Go port of the BasicStrategy from Passport.js's passport-http:
credentials arrive base64-encoded in the Authorization header, and a
user-supplied VerifyFunc maps the decoded username and password to an
application user.

Basic authentication is a good fit for simple, internal, or machine-to-machine
endpoints, admin tools, and health/metrics routes where a browser's built-in
credential prompt or a scripted client (curl -u, an SDK) is acceptable.
Because the credentials are sent on every request it should only be used over
HTTPS, and it is typically mounted statelessly with passport.Options{Session:
passport.NoSession()}.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/basic"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./basic/`.

```go
p := passport.New()

	p.Use(basic.New(func(username, password string) (user any, err error) {
		if username == "alice" && password == "s3cret" {
			return username, nil
		}
		return nil, basic.ErrInvalidCredentials
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/private", p.Authenticate("basic", passport.Options{Session: passport.NoSession()})(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates requests using HTTP Basic credentials. |
| `VerifyFunc` | VerifyFunc validates a username/password pair, returning the authenticated user on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a basic Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "basic". |

</details>

### Variables

`ErrInvalidCredentials`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/basic).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
