# custom — provides a generic adapter for defining ad-hoc authentication strategies inline

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/custom.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/custom)

Package custom provides a generic adapter for defining ad-hoc authentication
strategies inline, without writing a new type. It is the Go analogue of
Passport.js's passport-custom: instead of shipping a strategy package, you
pass a function that inspects the raw *http.Request and returns the
authenticated user. New wraps that function in a value that satisfies
passport.Strategy.

Use it as an escape hatch whenever no built-in strategy fits: a one-off header
or query-parameter check, an IP allowlist, a signed-URL verifier, an HMAC
webhook signature, a bridge to a bespoke or legacy auth service, or a quick
stub in tests. Anything you can decide from the request alone can become a
strategy in a few lines, and you register it under a name of your choosing so
it can sit alongside the other strategies you pass to passport.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/custom"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./custom/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Custom auth</title>
<script>
  // The AuthFunc authenticates on the X-API-Key header, so attach it to the
  // request to the protected route.
  fetch("/api", { headers: { "X-API-Key": "s3cret" } })
    .then(function (r) { return r.text(); })
    .then(console.log);
</script>
`)
	})

	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `AuthFunc` | AuthFunc inspects the request and returns the authenticated user, or nil to reject, or an error for an internal failure. |
| `Strategy` | Strategy adapts an AuthFunc to the passport.Strategy interface. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(name string, fn AuthFunc) *Strategy` | New creates a Strategy registered under name that authenticates with fn. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns the strategy name. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/custom).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
