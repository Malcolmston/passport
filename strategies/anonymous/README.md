# anonymous — pass-through authentication strategy for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/anonymous.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/anonymous)

Package anonymous implements a pass-through authentication strategy for the
passport port, a Go port of passport-anonymous. It never authenticates and
never fails: it simply declines to handle the request (it "passes"), allowing
the request to proceed with no authenticated user attached.

Its purpose is to make authentication optional on a route. Passport's
Authenticate normally responds with 401 when a strategy fails; by falling back
to the anonymous strategy you instead let unauthenticated requests through, so
a single handler can serve both signed-in users and guests. Typical uses are
public pages that show extra content when logged in, or APIs that personalize
a response only when a credential happens to be present.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/anonymous"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./anonymous/`.

```go
p := passport.New()

	p.Use(anonymous.New())

	greet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := passport.User(r); u != nil {
			_, _ = fmt.Fprintf(w, "hello, %v", u)
			return
		}
		_, _ = fmt.Fprint(w, "hello, guest")
	})

	mux := http.NewServeMux()

	mux.Handle("/", p.Authenticate("anonymous")(greet))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy always passes, leaving the request unauthenticated. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New() *Strategy` | New creates an anonymous Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy by declining to handle the request. |
| `func (s *Strategy) Name() string` | Name returns "anonymous". |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/anonymous).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
