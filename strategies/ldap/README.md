# ldap — username/password authentication strategy whose credential check is an LDAP "bind"

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/ldap.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/ldap)

Package ldap implements a username/password authentication strategy whose
credential check is an LDAP "bind" operation, a standard-library-only port in
the spirit of passport-ldapauth. Instead of comparing a password against a
local store, it authenticates the user by attempting to bind to a directory
server as that user — the canonical way to verify credentials against LDAP
or Active Directory.

Use this strategy when your users live in a corporate directory and you want
them to sign in with their directory username and password. Like the local
strategy it reads credentials from a submitted HTML form (fields default to
"username" and "password", overridable via UserField and PassField) and
establishes a passport session on success, so it slots into the same form-post
login route.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/ldap"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./ldap/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Log in</title>
<form method="post" action="/login">
  <input name="username" placeholder="Directory username">
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
| `BindFunc` | BindFunc performs the LDAP bind. |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy authenticates via an LDAP bind. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) DN(username string) string` | DN expands username into a distinguished name using DNTemplate. |
| `func (s *Strategy) Name() string` | Name returns "ldap". |

</details>

### Variables

`ErrInvalidCredentials`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/ldap).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
