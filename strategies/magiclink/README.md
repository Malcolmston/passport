# magiclink — implements passwordless "magic link" authentication

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/magiclink.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/magiclink)

Package magiclink implements passwordless "magic link" authentication, a
standard-library-only strategy in the spirit of passport-magic-login. Instead
of a password, the user proves control of an email address: the application
mints a signed, time-limited token, emails a link containing it, and the user
clicks through to be logged in. There is no third-party identity provider and
no stored password.

Use this strategy when you want frictionless email-based login. It has two
halves. First, an endpoint you write calls Sign to mint a token for the user's
email and embeds it in a link (for example
"https://app.example.com/verify?token=..."), which you deliver by email.
Second, the verify route you guard with this strategy reads the token from the
"?token=" query parameter, validates it, and — on success — reports the
email as the authenticated user for passport to serialize into the session.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/magiclink"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./magiclink/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<form method="post" action="/send">
  <input name="email" type="email" placeholder="you@example.com">
  <button type="submit">Email me a magic link</button>
</form>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Sign(secret []byte, email string, exp time.Time) string` | Sign builds a magic-link token for email that expires at exp. |

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the magiclink Strategy. |
| `Strategy` | Strategy authenticates requests presenting a valid, unexpired magic link. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a magiclink Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "magic-link". |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/magiclink).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
