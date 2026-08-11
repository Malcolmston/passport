# googleidtoken — verifies a Google-style OpenID Connect id_token that is presented directly

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/googleidtoken.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/googleidtoken)

Package googleidtoken verifies a Google-style OpenID Connect id_token that is
presented directly by the client — for example the JWT credential returned
by Google Sign-In or the Google Identity Services button — rather than
running the full OAuth 2.0 authorization-code redirect flow. It is the Go
analogue of Node's passport-google-id-token strategy and of
google-auth-library's verifyIdToken helper, packaged as a passport.Strategy
whose Name is "google-id-token".

Use this strategy when the browser already holds a signed id_token and simply
forwards it to your backend for validation, which is the common shape of
modern client-side Google Sign-In. Because there is no code exchange, no
client secret, redirect URI, or session round-trip to the provider is
involved; the backend's entire job is to prove the token is authentic,
unexpired, and intended for your application before trusting its claims.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/googleidtoken"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./googleidtoken/`.

```go
p := passport.New()

	p.Use(googleidtoken.New(googleidtoken.Options{
		JWKSURL:  googleidtoken.GoogleCertsURL,
		Audience: "YOUR_CLIENT_ID.apps.googleusercontent.com",
		Issuer:   "https://accounts.google.com",
	}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "signed in: %v", passport.User(r))
	})

	mux := http.NewServeMux()

	mux.Handle("/auth/google", p.Authenticate("google-id-token")(protected))

	log.Fatal(http.ListenAndServe(":3000", passport.Chain(mux, p.Initialize(), p.Session())))
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the strategy. |
| `Strategy` | Strategy verifies a Google-style id_token. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a Strategy from opts. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "google-id-token". |

</details>

### Constants

`GoogleCertsURL`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/googleidtoken).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
