# Passport for Go

`github.com/malcolmston/passport` is a Go port of the Node.js
[Passport](https://github.com/jaredhanson/passport) authentication middleware.
It provides pluggable, strategy-based authentication for `net/http` servers (and
anything built on `net/http`), using only the Go standard library in its core.

---

## How it works

### The Strategy contract

Every authentication mechanism — username/password, API key, bearer token, JWT,
OAuth2, OpenID Connect, WebAuthn — implements a single interface:

```go
type Strategy interface {
    // Name is the default name a strategy registers under, e.g. "local".
    Name() string
    // Authenticate runs the strategy against the request. It must record its
    // result on c before returning.
    Authenticate(c *Context, r *http.Request)
}
```

A strategy inspects the incoming request inside `Authenticate` and reports its
result by calling **exactly one** outcome method on the supplied `*Context`.
This mirrors Passport.js's `success` / `fail` / `redirect` / `error` / `pass`
contract, but as compiler-checked method calls instead of dynamically-dispatched
callbacks.

### Context outcomes

The five outcomes a strategy can record on the `*Context`:

| Method                      | Meaning                                                         | What `Authenticate` middleware does |
| --------------------------- | -------------------------------------------------------------- | ----------------------------------- |
| `c.Success(user, info...)`  | Credentials verified; here is the user.                        | Logs the user in (unless disabled), then runs the next handler or redirects to `SuccessRedirect`. |
| `c.Fail(challenge, status)` | Bad or missing credentials.                                    | Responds with the failure status (default 401) or redirects to `FailureRedirect`. |
| `c.Redirect(location, s)`   | Send the user agent elsewhere (e.g. to an identity provider).  | Issues an HTTP redirect. |
| `c.Error(err)`              | An internal error occurred.                                    | Responds `500`. |
| `c.Pass()`                  | This strategy declines to handle the request.                  | Continues the middleware chain, unauthenticated. |

`Result()` reports which one was called (`ResultSuccess`, `ResultFail`,
`ResultRedirect`, `ResultError`, `ResultPass`, or `ResultNone`) and is the basis
of the compliance runner below.

### Wiring and sessions

`Passport` is a registry of strategies plus the session and serialize logic:

- `p.Use(strategy)` registers a strategy under its `Name()`.
- `p.SerializeUser(fn)` reduces a user to a stable session id (typically its
  primary key); `p.DeserializeUser(fn)` reconstructs the user from that id.
- Three composable `net/http` middlewares drive a request:
  - `p.Initialize()` loads the session and installs the shared per-request
    authentication state.
  - `p.Session()` restores a logged-in user from the session on each request.
  - `p.Authenticate("name", opts...)` runs a named strategy and acts on its
    outcome.
- `p.LogIn` / `p.LogOut` establish and clear the login session (the equivalents
  of `req.login` / `req.logout`). `LogIn` regenerates the session id to prevent
  session fixation.
- `passport.User(r)` and `passport.IsAuthenticated(r)` read the current user.

Sessions are backed by a pluggable `Store` (an in-memory store ships by
default; swap in your own with `p.SetStore`). Middleware composes with
`passport.Chain(handler, mw...)`, which runs the first middleware outermost.

### Enforced strategy compliance

Two test files keep the whole catalog honest:

- `strategies/compliance_test.go` constructs a representative set of strategies
  and asserts, at runtime, that each implements `passport.Strategy`, returns a
  non-empty, lowercase, stable, unique `Name()`, and records **some** outcome on
  a blank request (never `ResultNone` — a strategy must never silently do
  nothing). OAuth2 providers additionally must resolve to a working
  `*oauth2.Strategy` and redirect on the first leg.
- `strategy_compliance_test.go` (in the root package) is a **static** runner: it
  parses every package under `strategies/` with `go/parser` and fails the build
  if a package neither provides a `passport.Strategy` (directly, or by
  delegating to a sibling base strategy) nor ships a `_test.go` file. A new
  strategy cannot merge without honoring the contract.

---

## How to use it

### 1. Local username/password strategy

```go
package main

import (
    "net/http"

    "github.com/malcolmston/passport"
    "github.com/malcolmston/passport/strategies/local"
)

type User struct {
    ID   string
    Name string
}

func main() {
    p := passport.New()

    // Register a local strategy. The verify function returns the user on
    // success, or (nil, nil) to fail authentication.
    p.Use(local.New(func(username, password string) (any, error) {
        if username == "alice" && password == "s3cret" {
            return &User{ID: "1", Name: "alice"}, nil
        }
        return nil, nil // reject
    }))

    // Serialize/Deserialize move the user in and out of the session.
    p.SerializeUser(func(user any) (string, error) {
        return user.(*User).ID, nil
    })
    p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
        return &User{ID: id, Name: "alice"}, nil
    })

    mux := http.NewServeMux()

    // POST /login runs the local strategy; on success it logs the user in and
    // redirects to "/".
    mux.Handle("/login", passport.Chain(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
        p.Authenticate("local", passport.Options{SuccessRedirect: "/"}),
    ))

    // "/" is guarded: unauthenticated requests are redirected to /login.
    mux.Handle("/", passport.Chain(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            u, _ := passport.User(r).(*User)
            w.Write([]byte("hello " + u.Name))
        }),
        p.RequireLogin("/login"),
    ))

    // Install the session middleware around the whole mux.
    handler := passport.Chain(mux, p.Initialize(), p.Session())
    http.ListenAndServe(":8080", handler)
}
```

### 2. An OAuth2 provider (GitHub)

Every OAuth2 provider is a thin preset over `strategies/oauth2`. The strategy
handles both legs: with no `?code` it redirects to the provider; on the callback
(with `?code`) it exchanges the code and reports success.

```go
package main

import (
    "net/http"

    "github.com/malcolmston/passport"
    "github.com/malcolmston/passport/strategies/github"
    "github.com/malcolmston/passport/strategies/oauth2"
)

func main() {
    p := passport.New()

    // clientID, clientSecret, redirectURL, and a verify func mapping the
    // fetched profile to your application's user.
    p.Use(github.New(
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
        "https://app.example.com/auth/github/callback",
        func(profile oauth2.Profile) (any, error) {
            // profile.ID and profile.Raw come from the provider's userinfo.
            return map[string]any{"id": profile.ID, "raw": profile.Raw}, nil
        },
    ))

    p.SerializeUser(func(u any) (string, error) {
        return u.(map[string]any)["id"].(string), nil
    })
    p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
        return map[string]any{"id": id}, nil
    })

    mux := http.NewServeMux()

    // Starting the flow: no ?code, so the strategy redirects to GitHub.
    mux.Handle("/auth/github", passport.Chain(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
        p.Authenticate("github"),
    ))

    // The callback: ?code is present, so the strategy exchanges it and logs in.
    mux.Handle("/auth/github/callback", passport.Chain(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
        p.Authenticate("github", passport.Options{
            SuccessRedirect: "/",
            FailureRedirect: "/login",
        }),
    ))

    handler := passport.Chain(mux, p.Initialize(), p.Session())
    http.ListenAndServe(":8080", handler)
}
```

The same shape works for 60+ providers (`google`, `gitlab`, `discord`,
`facebook`, `slack`, `stripe`, `okta`, `auth0`, `azuread`, ...), each with its
endpoints and default scopes preset.

### 3. JWT and JWKS

For symmetric (HS256) tokens, use `strategies/jwt`:

```go
import "github.com/malcolmston/passport/strategies/jwt"

// Verify HS256-signed bearer tokens. The verify func maps claims to a user.
strat := jwt.New([]byte("shared-secret"), func(claims jwt.Claims) (any, error) {
    return map[string]any{"sub": claims["sub"]}, nil
})
p.Use(strat) // reads "Authorization: Bearer <token>", verifies signature + exp/nbf
```

For providers that sign `id_token`s with rotating asymmetric keys published at a
JWKS endpoint (Google, Auth0, Okta, Azure AD, Cognito, ...), use
`strategies/jwks`. It fetches and caches keys, and refuses HS\* algorithms to
avoid key-confusion attacks:

```go
import (
    "time"

    "github.com/malcolmston/passport/strategies/jwks"
)

strat := jwks.New(jwks.Options{
    JWKSURL:    "https://www.googleapis.com/oauth2/v3/certs",
    Issuer:     "https://accounts.google.com",
    Audience:   "YOUR_CLIENT_ID",
    Algorithms: []string{"RS256"},
    CacheTTL:   time.Hour,
}, func(claims jwks.Claims) (any, error) {
    return map[string]any{"sub": claims.Subject()}, nil
})
p.Use(strat)
```

Both are stateless: register them and guard API routes with
`p.Authenticate("jwt")` / `p.Authenticate("jwks")` using
`passport.Options{Session: false}` when you do not want a login session created.

---

## Why it's better than its predecessor

This is an honest comparison against the Node.js
[jaredhanson/passport](https://github.com/jaredhanson/passport) ecosystem, which
this project ports. Different runtimes suit different projects; the points below
are the concrete tradeoffs.

- **Standard-library core, no dependency tree.** The root package and the
  session layer import only `net/http`, `context`, `crypto`, and friends. The
  Node ecosystem spreads authentication across `passport` plus dozens of
  independently-versioned `passport-*` strategy packages, each pulling its own
  transitive `node_modules`. Here there is no `node_modules` to audit, no
  lockfile drift, and no supply-chain surface beyond the Go toolchain.

- **Single static binary.** `go build` produces one self-contained executable
  with authentication compiled in — nothing to `npm install` at deploy time and
  no runtime to ship alongside it.

- **A type-safe strategy contract.** A strategy is a Go interface, checked at
  compile time. The outcome API (`Success` / `Fail` / `Redirect` / `Error` /
  `Pass`) is a set of methods, not stringly-typed callbacks, so a mis-wired
  strategy fails to compile rather than at 3 a.m. in production.

- **Enforced compliance.** Two compliance runners — one dynamic, one a static
  `go/parser` pass over the whole `strategies/` tree — make it impossible to add
  a strategy that skips the contract or ships without tests. Passport.js relies
  on convention and each strategy author's own test suite.

- **Batteries included.** 100+ strategy packages, including 60+ OAuth2 provider
  presets, an OAuth 1.0a core, JWT and JWKS, OpenID Connect, WebAuthn, SAML,
  LDAP, TOTP/HOTP, HMAC, magic-link, and the usual API-key / bearer / basic /
  digest token schemes — all in one module, versioned together.

- **Idiomatic `net/http`.** Middleware is the ordinary `func(http.Handler)
  http.Handler` shape, so it drops into `net/http`, `ServeMux`, chi, gorilla, or
  any router without adapters.

### Honest tradeoffs

- The Node ecosystem is older and larger; some niche third-party strategies have
  no port here yet. Adding one is a small package, but it is not automatic.
- The bundled OAuth 1.0a flow intentionally omits some session plumbing (see the
  `strategies/oauth1` package doc); production three-legged OAuth 1.0a needs you
  to persist the request-token secret.
- Being a port, the API deliberately tracks Passport.js's model rather than
  inventing a new one, so it inherits that model's shape (serialize/deserialize,
  named strategies) — familiar if you know Passport.js, opinionated if you do
  not.

---

For the full strategy catalog see [STRATEGIES.md](STRATEGIES.md); for
Passport.js compatibility notes see [COMPATIBILITY.md](COMPATIBILITY.md).
