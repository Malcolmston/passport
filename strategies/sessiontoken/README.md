# sessiontoken — authenticates requests by reading an opaque session token from a named cookie

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/sessiontoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/sessiontoken)

Package sessiontoken authenticates requests by reading an opaque session token
from a named cookie and validating it with a user-supplied Verify function
(typically a session-store lookup). It models the classic server-side session
pattern: the cookie carries only a meaningless identifier, and the real
session state lives on the server keyed by that identifier.

Use this strategy when you keep sessions in a store (in-memory, Redis, a
database, ...) and want passport to resolve the logged-in user from the
session cookie on each request. It is the stateful complement to
strategies/sessionjwt: because the token is opaque and validated against your
store, you can revoke a session instantly (delete the row) and change its
contents without re-issuing anything to the client — at the cost of a lookup
on every request.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/sessiontoken"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./sessiontoken/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <script>
      // The HttpOnly session cookie rides along because of credentials:"include".
      async function loadProfile() {
        const res = await fetch("/api/me", { credentials: "include" });
        if (!res.ok) { window.location = "/login"; return; }
        document.body.append(await res.text());
      }
      loadProfile();
    </script>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the sessiontoken Strategy. |
| `Strategy` | Strategy authenticates requests bearing a session-token cookie. |
| `VerifyFunc` | VerifyFunc validates a session token, returning the authenticated user. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a sessiontoken Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "session-token". |

</details>

### Variables

`ErrInvalidToken`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/sessiontoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
