# clientcredentials — implements OAuth2 client-credentials style authentication for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/clientcredentials.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/clientcredentials)

Package clientcredentials implements OAuth2 client-credentials style
authentication for the passport port. In the client-credentials grant (RFC
6749 §4.4) there is no end user and no browser: a client application proves
its own identity with a client_id and client_secret. This strategy reads that
pair from a request and hands it to a user-supplied VerifyFunc that decides
whether the client is authentic.

Use it for machine-to-machine (M2M) APIs -- a backend service, a cron job, a
webhook sender, or a partner integration calling your endpoints. Because there
is no interactive login, there is no redirect and no user-facing frontend;
clients simply attach their credentials to every request. Pair the strategy
with passport.Options{Session: passport.NoSession()} so no session cookie is
created for what is inherently a stateless call.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/clientcredentials"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./clientcredentials/`.

```go
req, err := http.NewRequest(http.MethodGet, "http://localhost:3000/api/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.SetBasicAuth("CLIENT_ID", "CLIENT_SECRET")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Strategy` | Strategy authenticates OAuth2 clients using the client-credentials grant. |
| `VerifyFunc` | VerifyFunc validates a client id/secret pair, returning the authenticated client (user) on success. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(verify VerifyFunc) *Strategy` | New creates a clientcredentials Strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "client-credentials". |

</details>

### Variables

`ErrInvalidClient`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/clientcredentials).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
