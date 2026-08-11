# trakt — provides an OAuth2 "Sign in with Trakt" authentication strategy for the passport port

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/trakt.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/trakt)

Package trakt provides an OAuth2 "Sign in with Trakt" authentication strategy
for the passport port. It is a thin preset over the shared strategies/oauth2
engine, filling in Trakt's authorization endpoint
(https://trakt.tv/oauth/authorize), token endpoint
(https://api.trakt.tv/oauth/token) and profile settings so callers only supply
their client credentials, redirect URL and a verify function.

The flow is the standard OAuth2 authorization-code grant driven by the
returned *oauth2.Strategy: an initiation request with no ?code= redirects the
browser to Trakt with the client ID, redirect URI, requested scopes and
optional state; the callback carries a ?code= that is exchanged for an access
token at the token endpoint. After the exchange the strategy GETs
https://api.trakt.tv/users/settings with the access token and hands the
decoded profile to verify.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/trakt"
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy configured for Trakt. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/trakt).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
