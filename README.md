# passport

[![Go Test](https://github.com/Malcolmston/passport/actions/workflows/go-test.yml/badge.svg)](https://github.com/Malcolmston/passport/actions/workflows/go-test.yml)
[![Go Lint](https://github.com/Malcolmston/passport/actions/workflows/go-lint.yml/badge.svg)](https://github.com/Malcolmston/passport/actions/workflows/go-lint.yml)
[![Go Vuln](https://github.com/Malcolmston/passport/actions/workflows/go-vuln.yml/badge.svg)](https://github.com/Malcolmston/passport/actions/workflows/go-vuln.yml)
[![Web Unit](https://github.com/Malcolmston/passport/actions/workflows/web-unit.yml/badge.svg)](https://github.com/Malcolmston/passport/actions/workflows/web-unit.yml)
[![Web E2E](https://github.com/Malcolmston/passport/actions/workflows/web-e2e.yml/badge.svg)](https://github.com/Malcolmston/passport/actions/workflows/web-e2e.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport.svg)](https://pkg.go.dev/github.com/malcolmston/passport)
[![Go Report Card](https://goreportcard.com/badge/github.com/malcolmston/passport)](https://goreportcard.com/report/github.com/malcolmston/passport)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Malcolmston/passport)](go.mod)
[![Release](https://img.shields.io/github/v/release/Malcolmston/passport?sort=semver)](https://github.com/Malcolmston/passport/releases)
[![Last Commit](https://img.shields.io/github/last-commit/Malcolmston/passport)](https://github.com/Malcolmston/passport/commits)
[![Code Size](https://img.shields.io/github/languages/code-size/Malcolmston/passport)](https://github.com/Malcolmston/passport)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Docs](https://img.shields.io/badge/docs-pages-2f9bff)](https://malcolmston.github.io/passport/)

**Node's Passport, for Go.**

`passport` is a Go port of [Passport.js](https://www.passportjs.org/) — simple,
pluggable authentication for `net/http` servers. Like the original, it separates
three concerns:

- **Strategies** verify credentials (the `local` username/password strategy
  ships in the box; custom strategies are a single interface).
- **Serialize / Deserialize** convert a user to and from a session id.
- **Middleware** (`Initialize`, `Session`, `Authenticate`) wires it into your
  handler chain.

It works with the standard library and with any framework built on `net/http`,
including its companion [`express`](https://github.com/malcolmston/express).

## Install

```sh
go get github.com/malcolmston/passport
```

## Quick start

```go
p := passport.New()

// 1. Register a strategy.
p.Use(local.New(func(username, password string) (any, error) {
	if username == "alice" && password == "password123" {
		return User{ID: "1", Name: "Alice"}, nil
	}
	return nil, local.ErrInvalidCredentials
}))

// 2. Teach passport how to persist a user in the session.
p.SerializeUser(func(u any) (string, error) { return u.(User).ID, nil })
p.DeserializeUser(func(id string, r *http.Request) (any, error) {
	return lookupUserByID(id), nil
})

// 3. Guard routes and build login/logout endpoints.
mux := http.NewServeMux()

mux.Handle("/login", p.Authenticate("local")(
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "welcome %v", passport.User(r))
	}),
))
mux.Handle("/profile", p.RequireLogin("/login")(profileHandler))

// 4. Install passport for every request.
handler := passport.Chain(mux, p.Initialize(), p.Session())
http.ListenAndServe(":3000", handler)
```

A runnable version lives in [`examples/basic`](examples/basic/main.go).

## How it fits together

| Piece | Role |
| ----- | ---- |
| `p.Initialize()` | per-request bootstrap: loads the session, installs auth state. Register it first. |
| `p.Session()` | restores a logged-in user from the session on each request. |
| `p.Authenticate(name, opts...)` | runs a strategy; on success attaches the user and (by default) logs in. |
| `p.RequireLogin(redirect)` | gate that lets only authenticated requests through. |
| `p.LogIn(w, r, user)` / `p.LogOut(w, r)` | establish or clear a session (Passport's `req.login` / `req.logout`). |
| `passport.User(r)` / `passport.IsAuthenticated(r)` | read the current user. |

`Chain(handler, mw...)` applies middleware with the first listed running
outermost — the same order you would register them.

## Sessions

By default `passport.New()` uses an in-memory session store and a
`passport.sid` cookie. The session id is regenerated on login to prevent
session-fixation. For production, plug in your own store:

```go
p.SetStore(myRedisStore) // any type implementing passport.Store
p.SecureCookies(true)     // send the session cookie only over HTTPS
```

For stateless authentication (API tokens, Basic auth), disable sessions per
route:

```go
p.Authenticate("bearer", passport.Options{Session: false})
```

## Options

`Authenticate` accepts an optional `passport.Options`:

| Field | Effect |
| ----- | ------ |
| `Session` | create a login session on success (default `true`). |
| `SuccessRedirect` | redirect here on success instead of calling `next`. |
| `FailureRedirect` | redirect here on failure instead of returning a status. |
| `FailureStatus` | override the failure status (default 401). |
| `FailureMessage` | write the strategy's challenge text as the failure body. |

## Bundled strategies

`passport` ships **55 strategies** under `strategies/` — see
[STRATEGIES.md](STRATEGIES.md) for the full catalog. Import the one you need and
register it with `p.Use`. The core credential strategies:

| Package | Strategy | Credentials |
| ------- | -------- | ----------- |
| `strategies/local` | username / password | form or JSON body |
| `strategies/basic` | HTTP Basic (RFC 7617) | `Authorization: Basic ...` |
| `strategies/bearer` | Bearer token (RFC 6750) | `Authorization: Bearer ...`, `access_token` param |
| `strategies/jwt` | JSON Web Token (HS256) | signed `Authorization: Bearer <jwt>` |
| `strategies/anonymous` | pass-through | none — makes auth optional |

Plus **20 OAuth2 providers** on a shared `strategies/oauth2` base (github,
google, facebook, gitlab, bitbucket, discord, slack, spotify, twitch, linkedin,
microsoft, apple, reddit, dropbox, yandex, amazon, stripe, twitter, okta,
auth0), **token/credential** strategies (apikey, hmac, totp, hotp, magic-link,
remember-me, signed-token, client-cert, digest, ...), and **federated** ones
(oauth1/twitter, openidconnect, jwt-bearer, cas, ldap, saml, ...).

Some enterprise/federated strategies are intentionally **simplified** (e.g.
`openidconnect`/`googleidtoken` verify HS256 rather than RS256/JWKS; `saml` does
not validate signatures; `ldap` delegates the bind to a caller-supplied
function). Each such package documents its limitations in its doc comment — see
[COMPATIBILITY.md](COMPATIBILITY.md).

```go
import (
	"github.com/malcolmston/passport/strategies/bearer"
	"github.com/malcolmston/passport/strategies/basic"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/anonymous"
)

// Opaque API tokens.
p.Use(bearer.New(func(token string) (any, error) {
	return lookupByToken(token) // (nil, bearer.ErrInvalidToken) to reject
}))

// HTTP Basic.
p.Use(basic.New(func(user, pass string) (any, error) {
	return authenticate(user, pass)
}))

// Stateless JWT (HS256). jwt.Sign is provided for issuing tokens.
p.Use(jwt.New([]byte(secret), func(c jwt.Claims) (any, error) {
	return lookupByID(c.Subject())
}))

// Optional auth: try a real strategy, then fall back to anonymous.
p.Use(anonymous.New())
```

The `jwt` strategy verifies the signature and the `exp` / `nbf` time claims
using only the standard library (no third-party dependencies), and exposes
`jwt.Sign(secret, claims)` for token issuance and `strategy.Parse(token)` for
manual verification.

## WebAuthn / passkeys

`strategies/webauthn` implements the WebAuthn (FIDO2 / passkey) ceremonies. The
authentication ceremony is fully verified — challenge, origin, RP ID hash, user
presence, the assertion signature (ES256 / RS256), and the signature counter —
using a built-in CBOR/COSE parser (no third-party dependencies).

```go
import "github.com/malcolmston/passport/strategies/webauthn"

cfg := webauthn.Config{RPID: "example.com", RPOrigin: "https://example.com", RPName: "Example"}

// Registration: serve options to the browser, then persist the credential.
challenge, options, _ := cfg.BeginRegistration(userID, "ada", "Ada Lovelace")
// ... store `challenge` in the session, send `options` as JSON ...
cred, _ := cfg.FinishRegistration(attestationObject, clientDataJSON, challenge)
// ... save cred (ID, PublicKey, SignCount) for the user ...

// Authentication: a passport strategy verifying the assertion.
p.Use(webauthn.New(cfg, myCredentialStore, func(r *http.Request) []byte {
	return sessionChallenge(r) // the challenge from BeginAuthentication
}))
```

Attestation-*statement* verification (proving the authenticator model) is
treated as `none` — the common default for passkeys — and documented as such.

## Writing a strategy

A strategy implements two methods and reports its result on the `*Context`:

```go
type BearerStrategy struct{ tokens map[string]User }

func (s *BearerStrategy) Name() string { return "bearer" }

func (s *BearerStrategy) Authenticate(c *passport.Context, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if u, ok := s.tokens[token]; ok {
		c.Success(u)     // authenticated
		return
	}
	c.Fail("invalid token", http.StatusUnauthorized) // rejected
}
```

Exactly one of `c.Success`, `c.Fail`, `c.Redirect`, `c.Error`, or `c.Pass`
should be called per attempt.

## Using with express

Because passport is plain `net/http` middleware and
[`express`](https://github.com/malcolmston/express) exposes the underlying
`req.Raw` / `res.Writer`, you can drive passport from an express handler:

```go
// Wrap a passport middleware as an express handler. passport stores its state
// on the request context, so we copy the updated request back onto req.Raw so
// downstream express handlers (and passport.User) can see it.
func passportMW(mw passport.Middleware) express.Handler {
	return func(req *express.Request, res *express.Response, next express.Next) {
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req.Raw = r // propagate passport's context-updated request
			next()      // passport allowed the request through
		})).ServeHTTP(res.Writer, req.Raw)
	}
}

app.Use(passportMW(p.Initialize()))
app.Use(passportMW(p.Session()))
app.Post("/login", passportMW(p.Authenticate("local")), func(req *express.Request, res *express.Response, next express.Next) {
	res.JSON(passport.User(req.Raw))
})
```

## Compatibility

A Go re-implementation modeled on Passport.js. Its JWT strategy is
**verified interoperable** with Node's `jsonwebtoken` (both directions), and all
strategies use standards-based wire formats. See
[COMPATIBILITY.md](COMPATIBILITY.md) for the parity tables, verified interop, and
known gaps.

## License

[MIT](LICENSE)
