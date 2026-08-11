# webauthn — implements WebAuthn (passkey / FIDO2) authentication for passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/webauthn.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/webauthn)

Package webauthn implements WebAuthn (passkey / FIDO2) authentication for
passport. It provides both ceremony halves — registration and authentication
— and a passport.Strategy that verifies a login assertion. It is the Go
counterpart to the passkey/WebAuthn strategies in the Passport.js ecosystem,
built entirely on the standard library (crypto, plus a small CBOR decoder)
with no external dependencies.

Reach for this package to offer passkeys: phishing-resistant, public-key
credentials that let users sign in with a platform authenticator (Touch ID,
Windows Hello, Android biometrics) or a roaming security key instead of a
password. Passkeys are a strong primary factor and a natural passwordless
replacement for username/password login, as well as a hardware-backed second
factor. Unlike the OAuth presets in this library there is no third-party
identity provider — your own site is the relying party and holds the
registered public keys.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/webauthn"
```

## Usage

This is the package's own `ExampleNew`, so it compiles and its output is
asserted on every `go test ./webauthn/`.

```go
cfg := webauthn.Config{
		RPID:     "localhost",
		RPOrigin: "http://localhost:3000",
		RPName:   "Passport Demo",
	}
	store := &credStore{byID: map[string]*webauthn.Credential{}, owner: map[string]string{}}

	// challenges maps a per-ceremony cookie value to the expected challenge.
	var mu sync.Mutex
	challenges := map[string][]byte{}
	challengeFor := func(r *http.Request) []byte {
		c, err := r.Cookie("wa_ceremony")
		if err != nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		return challenges[c.Value]
	}

	p := passport.New()
	p.Use(webauthn.New(cfg, store, challengeFor))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	mux.HandleFunc("/login/begin", func(w http.ResponseWriter, r *http.Request) {
		challenge, _, err := cfg.BeginAuthentication(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		challenges["ceremony-id"] = challenge
		mu.Unlock()

	})

	mux.Handle("/login/finish", p.Authenticate("webauthn")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("authenticated " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func NewChallenge() ([]byte, error)` | NewChallenge returns 32 cryptographically-random challenge bytes. |

### Types

| Type | What it is |
| --- | --- |
| `ChallengeFunc` | ChallengeFunc returns the challenge expected for this request (typically read from the user's session where BeginAuthentication stored it). |
| `Config` | Config describes the relying party (your site). |
| `Credential` | Credential is a registered public-key credential to be persisted by the application and looked up during authentication. |
| `SignCountUpdater` | SignCountUpdater is an optional Store extension: when implemented, the strategy reports the new signature counter after a successful assertion so it… |
| `Store` | Store looks up a registered credential by its id and returns the associated user. |
| `Strategy` | Strategy authenticates a WebAuthn assertion. |

<details>
<summary><code>Config</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func (c *Config) BeginAuthentication(allowCredentialIDs [][]byte) ([]byte, map[string]any, error)` | BeginAuthentication builds PublicKeyCredentialRequestOptions for the browser. |
| `func (c *Config) BeginRegistration(userID, userName, displayName string) ([]byte, map[string]any, error)` | BeginRegistration builds PublicKeyCredentialCreationOptions for the browser. |
| `func (c *Config) FinishRegistration(attestationObject, clientDataJSON, expectedChallenge []byte) (*Credential, error)` | FinishRegistration parses a registration response's attestation object and clientDataJSON, verifies the challenge and origin, and returns the… |

</details>

<details>
<summary><code>Strategy</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(cfg Config, store Store, challenge ChallengeFunc) *Strategy` | New creates a WebAuthn authentication strategy. |
| `func (s *Strategy) Authenticate(c *passport.Context, r *http.Request)` | Authenticate implements passport.Strategy. |
| `func (s *Strategy) Name() string` | Name returns "webauthn". |

</details>

### Variables

`ErrBadAttestation`, `ErrUnsupportedKey`, `ErrVerification`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/webauthn).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
