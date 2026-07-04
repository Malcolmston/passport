# passport — JavaScript adapter (WebAssembly)

Run the **same Go implementation** of passport's token utilities from
JavaScript — in the browser or Node — via WebAssembly. No reimplementation:
`main.go` exposes passport's portable, pure JWT/OTP functions to JS and
`passport.mjs` wraps them in an idiomatic API.

Only the pure, portable token/OTP helpers are exposed. The `net/http` Strategy
middleware (the OAuth/session/request machinery) is intentionally left out — it
has no meaning outside a server.

## Build

```sh
./build.sh          # produces passport.wasm (+ copies the Go wasm_exec.js runtime)
```

## Use (Node or browser)

```js
import { loadPassport } from './passport.mjs';
const passport = await loadPassport();

// JWT (HS256)
const token  = passport.jwtSign({ sub: 'abc', role: 'admin' }, 'secret');
const claims = passport.jwtVerify(token, 'secret');   // { sub:'abc', role:'admin' } | null

// TOTP (RFC 6238) / HOTP (RFC 4226) over a base32 secret
passport.totpGenerate('GEZDGNBVGY3TQOJQ');            // current 6-digit code
passport.totpGenerate('GEZDGNBVGY3TQOJQ', 59);        // code at a fixed Unix time
passport.totpVerify('GEZDGNBVGY3TQOJQ', '287082');    // true | false (±1 step)
passport.hotpGenerate('GEZDGNBVGY3TQOJQ', 0);         // HOTP code at counter 0
```

### Exposed functions

| JS function | Go source | Notes |
|---|---|---|
| `jwtSign(claims, secret)` | `jwt.Sign` | HS256; returns the compact token (or `null`) |
| `jwtVerify(token, secret)` | `(*jwt.Strategy).Parse` | returns claims object, or `null` if invalid |
| `totpGenerate(secret[, unixSeconds])` | `totp.Generate` | base32 secret; time defaults to now |
| `totpVerify(secret, code[, unixSeconds])` | `totp.Generate` | matches within ±1 time step |
| `hotpGenerate(secret, counter)` | `hotp.Generate` | base32 secret |

## Verify

```sh
./build.sh && node test.mjs
```

The adapter is compiled with `GOOS=js GOARCH=wasm`; on normal platforms
`stub.go` keeps `go build ./...` and CI green. Build artifacts (`*.wasm`) are
gitignored.
