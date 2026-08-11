# totp — implements Time-based One-Time Password (TOTP) authentication as specified in RFC 6238

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/totp.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/totp)

Package totp implements Time-based One-Time Password (TOTP) authentication as
specified in RFC 6238 (HMAC-SHA1, 6 digits, 30-second time step). It is the Go
port of the passport-totp strategy from the Passport.js ecosystem, and is the
second-factor building block behind the "enter the 6-digit code from your
authenticator app" experience offered by Google Authenticator, Authy,
1Password, and similar apps.

Reach for this package to add a time-based one-time-password second factor
(2FA/MFA) to an application, or as a passwordless primary factor when the user
has already enrolled a shared secret. It pairs naturally with a primary
strategy such as the local username/password strategy: authenticate the
password first, then require a valid TOTP code before establishing the login
session. Because the algorithm is fully standardized, any RFC 6238
authenticator app interoperates without provider-specific code.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/totp"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./totp/`.

```go
secrets := map[string][]byte{
		"alice": []byte("12345678901234567890"),
	}

	p := passport.New()

	p.Use(totp.New(totp.Options{
		Secret: func(user string) ([]byte, error) {
			return secrets[user], nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	mux.Handle("/verify", p.Authenticate("totp")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("verified " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Generate(secret []byte, t time.Time) string` | Generate returns the RFC 6238 TOTP value for the given secret at time t. |

### Types

| Type | What it is |
| --- | --- |
| `Options` | Options configures the totp Strategy. |
| `Strategy` | Strategy authenticates requests presenting a time-based one-time password. |

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(opts Options) *Strategy` | New creates a totp Strategy, applying defaults for any zero-valued option. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "totp". |

</details>

### Constants

`Digits`, `Step`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/totp).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
