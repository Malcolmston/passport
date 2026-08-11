# hmac — authenticates requests by verifying an HMAC-SHA256 signature of the raw request body

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/hmac.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hmac)

Package hmac authenticates requests by verifying an HMAC-SHA256 signature of
the raw request body. It ports the HMAC request-signing pattern seen in the
Passport.js ecosystem (passport-hmac) and in widely used webhook signature
schemes such as Stripe's and GitHub's, using only the Go standard library.

Use this strategy to authenticate webhook deliveries and other machine-to-
machine POST requests where the sender and receiver share a secret and the
sender signs each payload. Because the signature covers the exact bytes of the
body, it authenticates the caller and guarantees the payload was not altered
in transit, without any interactive handshake or session. This makes it well
suited to receiving events from third-party providers that sign their
callbacks, or to securing internal service-to-service notifications.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/hmac"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./hmac/`.

```go
p := passport.New()

	secrets := map[string][]byte{"client-1": []byte("shared-secret")}

	p.Use(hmac.New(hmac.Options{
		Header:      "X-Signature",
		KeyIDHeader: "X-Key-Id",
		Secret: func(keyID string) []byte {
			return secrets[keyID]
		},
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "verified webhook from %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/webhook", p.Authenticate("hmac")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the hmac Strategy. |
| `Strategy` | Strategy authenticates requests bearing an HMAC-SHA256 body signature. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates an hmac Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "hmac". |

</details>

### Constants

`DefaultMaxBodyBytes`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/hmac).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
