# bungie — provides an OAuth2 "Sign in with Bungie" authentication strategy for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/bungie.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bungie)

Package bungie provides an OAuth2 "Sign in with Bungie" authentication
strategy for the passport port. It is a thin preset over the shared
strategies/oauth2 engine, filling in Bungie's authorization endpoint
(https://www.bungie.net/en/OAuth/Authorize), token endpoint
(https://www.bungie.net/Platform/App/OAuth/Token/) and profile settings so
callers only supply their client credentials, redirect URL and a verify
function.

The flow is the standard OAuth2 authorization-code grant driven by the
returned *oauth2.Strategy: an initiation request with no ?code= redirects the
browser to Bungie with the client ID, redirect URI, requested scopes and
optional state; the callback carries a ?code= that is exchanged for an access
token at the token endpoint. This provider exposes no userinfo endpoint here,
so the resulting oauth2.Profile carries only the access token and the verify
function is responsible for loading identity via the provider API.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/bungie"
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Bungie. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/bungie).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
