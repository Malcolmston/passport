# oauthstate — provides CSRF "state" handling for OAuth 2.0 authorization-code flows in the passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/oauthstate.svg)](https://pkg.go.dev/github.com/malcolmston/passport/oauthstate)

Package oauthstate provides CSRF "state" handling for OAuth 2.0
authorization-code flows in the passport port. The strategies/oauth2 base
passes the state parameter through opaquely but neither generates nor
validates it; this package fills that gap, mirroring the state-store concept
from Node's passport-oauth2.

Two independent styles are offered. A stateful MemoryStore issues a random
nonce, remembers it (optionally with an application-defined payload), and
consumes it exactly once on the callback — the classic server-side approach.
A stateless HMACStore instead signs a payload with a secret key so the state
is self-verifying and needs no server storage, at the cost of the state string
being larger and, if a payload is attached, visible to the user agent.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/oauthstate"
```

## Usage

This is the package's own `ExampleHMACStore`, so it compiles and its output is
asserted on every `go test ./oauthstate/`.

```go
store := oauthstate.NewHMACStore([]byte("a-32-byte-or-longer-secret-key!!"), 5*time.Minute)

	state, err := store.Issue("/settings")
	if err != nil {
		panic(err)
	}

	returnTo, err := store.Verify(state)
	fmt.Println("return to:", returnTo, "err:", err)

	_, err = store.Verify(state + "x")
	fmt.Println("tampered:", err)
```

```
return to: /settings err: <nil>
tampered: oauthstate: signature mismatch
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func Equal(a, b string) bool` | Equal reports whether two state values are identical, comparing them in constant time. |
| `func GenerateNonce() (string, error)` | GenerateNonce returns a URL-safe random string built from 16 bytes of entropy, suitable as an OAuth state value or general CSRF token. |
| `func GenerateNonceWithLength(n int) (string, error)` | GenerateNonceWithLength returns a URL-safe random string built from n bytes of entropy. |

### Types

| Type | What it is |
| --- | --- |
| `HMACStore` | HMACStore is a stateless Store: the state string is the base64url of a random nonce and optional payload, authenticated by an HMAC-SHA256 tag over… |
| `MemoryStore` | MemoryStore is a single-request, server-side Store. |
| `Store` | Store issues opaque state values and verifies them on the OAuth callback. |

<details>
<summary><code>HMACStore</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewHMACStore(key []byte, ttl time.Duration) *HMACStore` | NewHMACStore returns an HMACStore that signs with key. |
| `func (s *HMACStore) Issue(payload string) (string, error)` | Issue returns a signed state of the form base64url(nonce)."."base64url(unixSeconds)."."base64url(payload)."."tag. |
| `func (s *HMACStore) Verify(state string) (string, error)` | Verify recomputes the signature over a returned state and, on a match, returns the embedded payload. |

</details>

<details>
<summary><code>MemoryStore</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func NewMemoryStore(ttl time.Duration) *MemoryStore` | NewMemoryStore returns a MemoryStore whose issued states expire after ttl. |
| `func (s *MemoryStore) Issue(payload string) (string, error)` | Issue generates a nonce, stores payload against it, and returns the nonce. |
| `func (s *MemoryStore) Len() int` | Len reports how many issued-but-unconsumed states the store currently holds, including any that have expired but not yet been swept. |
| `func (s *MemoryStore) Sweep() int` | Sweep discards every issued-but-unconsumed state whose TTL has elapsed and reports how many were removed. |
| `func (s *MemoryStore) Verify(state string) (string, error)` | Verify consumes state, returning the payload that was stored with it. |

</details>

### Variables

`ErrUnknownState`, `ErrBadSignature`

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/oauthstate).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
