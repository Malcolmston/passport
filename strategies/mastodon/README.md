# mastodon — provides a passport OAuth2 strategy preset for Mastodon, the federated

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies/mastodon.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies/mastodon)

Package mastodon provides a passport OAuth2 strategy preset for Mastodon, the
federated, self-hostable social network. It is a thin wrapper over
strategies/oauth2 and ports passport-mastodon: New and NewWithDomain return a
*oauth2.Strategy, so the full OAuth2 base API and its documented semantics
apply here unchanged.

Use this package to let users log in with a Mastodon account. Because Mastodon
is not a single service but a federation of independent instances, its OAuth2
endpoints are derived from an instance host rather than being fixed. Prefer
NewWithDomain, which builds the endpoints from the instance host you supply
(for example "mastodon.social", without a scheme); New exists for convenience
and uses a placeholder instance you will usually want to override. Register an
application on the target instance to obtain its client credentials.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/mastodon"
```

## Usage

This is the package's own `Example_frontend`, so it compiles and its output is
asserted on every `go test ./mastodon/`.

```go
mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Sign in</title>
<a href="/auth/mastodon">Sign in with Mastodon</a>`))
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
```

## Exported surface

### Functions

| Function | What it does |
| --- | --- |
| `func New(clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | New returns an OAuth2 strategy for Mastodon using the placeholder instance. |
| `func NewWithDomain(instance, clientID, clientSecret, redirectURL string, verify oauth2.VerifyFunc) *oauth2.Strategy` | NewWithDomain returns an OAuth2 strategy for the given Mastodon instance host (e.g. |

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/strategies/mastodon).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](../..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
