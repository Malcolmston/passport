# strategies — the credential verifiers passport authenticates with

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/strategies.svg)](https://pkg.go.dev/github.com/malcolmston/passport/strategies)

This directory is not a Go package of its own — it holds no non-test source.
It is the namespace under which every bundled
[`passport.Strategy`](https://pkg.go.dev/github.com/malcolmston/passport#Strategy)
lives, one importable package each, so a program links only the providers it
actually uses.

The two test files at this level are cross-cutting: `strategies_test.go` drives
a representative set of strategies through the full passport middleware stack,
and `compliance_test.go` asserts the contract *every* strategy must honour —
it implements `passport.Strategy`, `Name()` returns a stable non-empty
lowercase token unique across the set, and `Authenticate` on a blank request
always records some outcome rather than silently doing nothing.

```sh
go test ./strategies/
```

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/strategies/local"
```

## The 154 bundled strategies

Each subdirectory has its own README with its exported surface and, where the
package ships one, a compiling example.

### Mechanism strategies (36)

These implement an authentication *mechanism* rather than wrapping a named
provider: the token, password, certificate and challenge-response families,
plus the three generic engines (`oauth1`, `oauth2`, `openidconnect`) the
provider presets are built on.

| | | | | | |
| --- | --- | --- | --- | --- | --- |
| [`anonymous`](anonymous) | [`apikey`](apikey) | [`apitoken`](apitoken) | [`basic`](basic) | [`basicverify`](basicverify) | [`bearer`](bearer) |
| [`bearertoken`](bearertoken) | [`cas`](cas) | [`clientcert`](clientcert) | [`clientcredentials`](clientcredentials) | [`cookietoken`](cookietoken) | [`custom`](custom) |
| [`digest`](digest) | [`googleidtoken`](googleidtoken) | [`headertoken`](headertoken) | [`hmac`](hmac) | [`hotp`](hotp) | [`jwks`](jwks) |
| [`jwt`](jwt) | [`jwtbearer`](jwtbearer) | [`ldap`](ldap) | [`local`](local) | [`magiclink`](magiclink) | [`oauth1`](oauth1) |
| [`oauth2`](oauth2) | [`openidconnect`](openidconnect) | [`querytoken`](querytoken) | [`refreshjwt`](refreshjwt) | [`refreshtoken`](refreshtoken) | [`remembercookie`](remembercookie) |
| [`saml`](saml) | [`sessionjwt`](sessionjwt) | [`sessiontoken`](sessiontoken) | [`signedtoken`](signedtoken) | [`totp`](totp) | [`webauthn`](webauthn) |

### OAuth2 provider presets (117)

Thin presets over the shared [`oauth2`](oauth2) engine. Each fills in one
provider's authorization endpoint, token endpoint and profile settings, so a
caller supplies only client credentials, a redirect URL and a verify function:

```go
p.Use(github.New(clientID, clientSecret, "https://example.com/auth/callback",
    func(p oauth2.Profile) (any, error) {
        return lookupOrCreateUser(p.ID)
    }))
```

| | | | | | |
| --- | --- | --- | --- | --- | --- |
| [`adobe`](adobe) | [`airtable`](airtable) | [`amazon`](amazon) | [`apple`](apple) | [`arcgis`](arcgis) | [`asana`](asana) |
| [`atlassian`](atlassian) | [`auth0`](auth0) | [`azuread`](azuread) | [`battlenet`](battlenet) | [`bitbucket`](bitbucket) | [`bitly`](bitly) |
| [`box`](box) | [`buffer`](buffer) | [`bungie`](bungie) | [`calendly`](calendly) | [`canva`](canva) | [`clickup`](clickup) |
| [`cognito`](cognito) | [`coinbase`](coinbase) | [`dailymotion`](dailymotion) | [`deezer`](deezer) | [`deviantart`](deviantart) | [`digitalocean`](digitalocean) |
| [`discord`](discord) | [`docusign`](docusign) | [`dropbox`](dropbox) | [`ebay`](ebay) | [`epicgames`](epicgames) | [`etsy`](etsy) |
| [`eventbrite`](eventbrite) | [`facebook`](facebook) | [`feedly`](feedly) | [`figma`](figma) | [`fitbit`](fitbit) | [`fortytwo`](fortytwo) |
| [`foursquare`](foursquare) | [`freshbooks`](freshbooks) | [`gitea`](gitea) | [`gitee`](gitee) | [`github`](github) | [`gitlab`](gitlab) |
| [`google`](google) | [`gumroad`](gumroad) | [`heroku`](heroku) | [`hubspot`](hubspot) | [`imgur`](imgur) | [`instagram`](instagram) |
| [`intuit`](intuit) | [`kakao`](kakao) | [`keycloak`](keycloak) | [`line`](line) | [`linear`](linear) | [`linkedin`](linkedin) |
| [`mailchimp`](mailchimp) | [`mailru`](mailru) | [`mastodon`](mastodon) | [`medium`](medium) | [`meetup`](meetup) | [`mercadolibre`](mercadolibre) |
| [`microsoft`](microsoft) | [`miro`](miro) | [`mixcloud`](mixcloud) | [`monday`](monday) | [`naver`](naver) | [`nightbot`](nightbot) |
| [`notion`](notion) | [`okta`](okta) | [`onelogin`](onelogin) | [`openstreetmap`](openstreetmap) | [`orcid`](orcid) | [`osu`](osu) |
| [`oura`](oura) | [`patreon`](patreon) | [`paypal`](paypal) | [`pinterest`](pinterest) | [`pipedrive`](pipedrive) | [`producthunt`](producthunt) |
| [`reddit`](reddit) | [`salesforce`](salesforce) | [`sentry`](sentry) | [`shopify`](shopify) | [`slack`](slack) | [`smartsheet`](smartsheet) |
| [`snapchat`](snapchat) | [`soundcloud`](soundcloud) | [`spotify`](spotify) | [`square`](square) | [`stackexchange`](stackexchange) | [`strava`](strava) |
| [`streamlabs`](streamlabs) | [`stripe`](stripe) | [`surveymonkey`](surveymonkey) | [`tiktok`](tiktok) | [`todoist`](todoist) | [`trakt`](trakt) |
| [`twitch`](twitch) | [`twitter`](twitter) | [`typeform`](typeform) | [`uber`](uber) | [`unsplash`](unsplash) | [`vimeo`](vimeo) |
| [`vk`](vk) | [`wakatime`](wakatime) | [`webex`](webex) | [`webflow`](webflow) | [`wechat`](wechat) | [`weibo`](weibo) |
| [`whoop`](whoop) | [`wordpresscom`](wordpresscom) | [`workos`](workos) | [`xero`](xero) | [`yahoo`](yahoo) | [`yandex`](yandex) |
| [`zendesk`](zendesk) | [`zoho`](zoho) | [`zoom`](zoom) | | | |

### OAuth1 provider presets (1)

| | | | | | |
| --- | --- | --- | --- | --- | --- |
| [`oauth1twitter`](oauth1twitter) | | | | | |

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
