# passport

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

Import the strategy you need from `strategies/` and register it with `p.Use`:

| Package | Strategy | Credentials |
| ------- | -------- | ----------- |
| `strategies/local` | username / password | form or JSON body |
| `strategies/basic` | HTTP Basic (RFC 7617) | `Authorization: Basic ...` |
| `strategies/bearer` | Bearer token (RFC 6750) | `Authorization: Bearer ...`, `access_token` param |
| `strategies/jwt` | JSON Web Token (HS256) | signed `Authorization: Bearer <jwt>` |
| `strategies/anonymous` | pass-through | none — makes auth optional |

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

## License

[MIT](LICENSE)
