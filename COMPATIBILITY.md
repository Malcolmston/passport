# Compatibility

`passport` is a Go re-implementation of Passport.js — it mirrors Passport's
model (strategies, serialize/deserialize, middleware) with an idiomatic Go API.
It is **not** a drop-in for the Node package (different language), but every
place a real **wire format** is involved, it follows the same standards the
Node ecosystem uses, so it interoperates with Node-issued credentials.

## Verified interop

| Format | Standard | Verified against | Result |
| ------ | -------- | ---------------- | ------ |
| JWT (HS256) | RFC 7519 | `jsonwebtoken@9` (Node) | ✅ both directions — see [`interop/`](interop/) |

`jwt.Sign` tokens verify in Node's `jsonwebtoken`; tokens signed by
`jsonwebtoken` verify here; wrong-secret tokens are rejected.

## Strategy parity with Passport.js

| Passport.js | This library | Notes |
| ----------- | ------------ | ----- |
| `passport-local` | `strategies/local` | form + JSON bodies, configurable field names |
| `passport-http` (Basic) | `strategies/basic` | RFC 7617; `WWW-Authenticate` challenge |
| `passport-http-bearer` | `strategies/bearer` | RFC 6750; header/query/form token |
| `passport-jwt` | `strategies/jwt` | HS256, `exp`/`nbf`, stdlib-only |
| `passport-anonymous` | `strategies/anonymous` | pass-through |

The `Strategy` interface matches Passport's contract: a strategy reports exactly
one outcome per attempt — `Success` / `Fail` / `Redirect` / `Error` / `Pass`.

## Core API parity

| Passport.js | This library |
| ----------- | ------------ |
| `passport.use(strategy)` | `p.Use(strategy)` / `p.UseNamed(name, s)` |
| `passport.serializeUser` | `p.SerializeUser` |
| `passport.deserializeUser` | `p.DeserializeUser` |
| `passport.initialize()` | `p.Initialize()` |
| `passport.session()` | `p.Session()` |
| `passport.authenticate(name, opts)` | `p.Authenticate(name, opts)` |
| `req.login` / `req.logout` | `p.LogIn` / `p.LogOut` |
| `req.user` / `req.isAuthenticated()` | `passport.User(r)` / `passport.IsAuthenticated(r)` |
| `successRedirect` / `failureRedirect` | `Options.SuccessRedirect` / `FailureRedirect` |
| `session: false` | `Options.Session = false` |

Session cookies use HTTP-standard `Set-Cookie` (HttpOnly, Secure, SameSite),
and the session id is regenerated on login to prevent fixation — matching
`express-session`/Passport guidance.

## Simplified strategies

Some federated strategies implement a correct **core** but simplify parts that
would require asymmetric crypto, network protocols, or session storage beyond
the standard library. Each documents this in its package doc comment:

| Strategy | Simplification |
| -------- | -------------- |
| `openidconnect`, `googleidtoken`, `jwtbearer` | verify id_token/assertion as **HS256** shared-secret rather than RS256/JWKS |
| `saml` | parses `SAMLResponse` and extracts `NameID` but performs **no signature validation** — wiring/testing only, not production-secure |
| `ldap` | no network bind; delegates to a caller-supplied `Bind(dn, password)` integration point |
| `cas` | CAS 2.0 `serviceValidate` flow; no proxy tickets |
| `oauth1` | signing/flow complete; access-token exchange uses an empty token secret (request-token secret needs session storage) |

The OAuth2 providers, JWT (HS256), TOTP/HOTP (RFC 6238/4226), HMAC, and HTTP
Basic/Bearer strategies are full implementations verified with tests (and, for
JWT, cross-verified against Node).

## Known gaps

Passport.js has 500+ community strategies; this library ships the most common
five and a clean interface for adding more. Not implemented:

- OAuth 1.0/2.0 and OpenID Connect strategies (Google, GitHub, etc.).
- `connect-flash` integration for flash messages.
- `passReqToCallback`-style verify variants (the verify functions here take the
  parsed credentials directly; use a closure to capture request state).
- Multi-strategy `authenticate([...])` fallback chaining in a single call
  (compose with the `anonymous` strategy or middleware instead).
