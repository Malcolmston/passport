# shopify — provides a passport OAuth2 strategy preset for Shopify

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/shopify.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/shopify)

Package shopify provides a passport OAuth2 strategy preset for Shopify,
porting the passport-shopify strategy from the Passport.js ecosystem. It is a
thin configuration layer over strategies/oauth2: it fills in Shopify's
per-shop authorization and token endpoints so callers only supply their app's
API key and secret, a redirect URL and a verify function.

Use this preset when you build a Shopify app that authorizes against a
merchant's store. Shopify is per-shop: every store is served from its own
{shop}.myshopify.com host, so the endpoints must be built from that domain.
New uses a placeholder shop domain ("example.myshopify.com") so the
zero-configuration call compiles and is discoverable; real deployments must
call NewWithDomain with the merchant's actual myshopify.com domain (which your
app typically learns from the ?shop parameter Shopify sends when the install
begins).

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/shopify"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./shopify/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <body>
    <!-- Anchor to the server route that starts the OAuth2 redirect. -->
    <a href="/auth/shopify">Sign in with Shopify</a>
  </body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Shopify using the placeholder shop domain ("example.myshopify.com"). |
| `func NewWithDomain(domain, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Shopify store domain (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/shopify).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
