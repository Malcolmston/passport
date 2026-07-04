# Strategy catalog

`passport` ships **56 authentication strategies** under `strategies/`.
Each is an independent subpackage implementing `passport.Strategy`, with a `New(...)`
constructor. Standard library only.

| Strategy | Import | Description |
| -------- | ------ | ----------- |
| `amazon` | `github.com/malcolmston/passport/strategies/amazon` | provides a passport OAuth2 strategy preset for the Amazon |
| `anonymous` | `github.com/malcolmston/passport/strategies/anonymous` | implements a pass-through strategy, a Go port of |
| `apikey` | `github.com/malcolmston/passport/strategies/apikey` | implements API-key authentication. The key is read from a |
| `apitoken` | `github.com/malcolmston/passport/strategies/apitoken` | authenticates requests bearing an opaque API token. The |
| `apple` | `github.com/malcolmston/passport/strategies/apple` | provides a passport OAuth2 strategy preset for the Apple |
| `auth0` | `github.com/malcolmston/passport/strategies/auth0` | provides a passport OAuth2 strategy preset for Auth0. Auth0 is |
| `basic` | `github.com/malcolmston/passport/strategies/basic` | implements HTTP Basic authentication (RFC 7617), a Go port of |
| `basicverify` | `github.com/malcolmston/passport/strategies/basicverify` | implements HTTP Basic authentication (RFC 7617) with a |
| `bearer` | `github.com/malcolmston/passport/strategies/bearer` | implements HTTP Bearer token authentication (RFC 6750), a Go |
| `bearertoken` | `github.com/malcolmston/passport/strategies/bearertoken` | implements opaque bearer-token authentication via token |
| `bitbucket` | `github.com/malcolmston/passport/strategies/bitbucket` | provides a passport OAuth2 strategy preset for the Bitbucket |
| `cas` | `github.com/malcolmston/passport/strategies/cas` | implements a client for the CAS (Central Authentication Service) |
| `clientcert` | `github.com/malcolmston/passport/strategies/clientcert` | implements TLS client-certificate (mutual TLS) |
| `clientcredentials` | `github.com/malcolmston/passport/strategies/clientcredentials` | implements OAuth2 client-credentials style |
| `cookietoken` | `github.com/malcolmston/passport/strategies/cookietoken` | authenticates requests by reading a token from a named |
| `custom` | `github.com/malcolmston/passport/strategies/custom` | provides a generic adapter for defining ad-hoc authentication |
| `digest` | `github.com/malcolmston/passport/strategies/digest` | implements a SIMPLIFIED form of HTTP Digest access |
| `discord` | `github.com/malcolmston/passport/strategies/discord` | provides a passport OAuth2 strategy preset for the Discord |
| `dropbox` | `github.com/malcolmston/passport/strategies/dropbox` | provides a passport OAuth2 strategy preset for the Dropbox |
| `facebook` | `github.com/malcolmston/passport/strategies/facebook` | provides a passport OAuth2 strategy preset for the Facebook |
| `github` | `github.com/malcolmston/passport/strategies/github` | provides a passport OAuth2 strategy preset for the Github |
| `gitlab` | `github.com/malcolmston/passport/strategies/gitlab` | provides a passport OAuth2 strategy preset for the Gitlab |
| `google` | `github.com/malcolmston/passport/strategies/google` | provides a passport OAuth2 strategy preset for the Google |
| `googleidtoken` | `github.com/malcolmston/passport/strategies/googleidtoken` | verifies a Google-style OpenID Connect id_token |
| `headertoken` | `github.com/malcolmston/passport/strategies/headertoken` | authenticates requests by reading a token from an |
| `hmac` | `github.com/malcolmston/passport/strategies/hmac` | authenticates requests by verifying an HMAC-SHA256 signature of |
| `hotp` | `github.com/malcolmston/passport/strategies/hotp` | implements HMAC-based One-Time Password (HOTP) authentication as |
| `jwt` | `github.com/malcolmston/passport/strategies/jwt` | implements a JSON Web Token authentication strategy, a Go port of |
| `jwtbearer` | `github.com/malcolmston/passport/strategies/jwtbearer` | implements the JWT Bearer authorization grant of RFC 7523 |
| `ldap` | `github.com/malcolmston/passport/strategies/ldap` | implements a username/password strategy whose credential check |
| `linkedin` | `github.com/malcolmston/passport/strategies/linkedin` | provides a passport OAuth2 strategy preset for the Linkedin |
| `local` | `github.com/malcolmston/passport/strategies/local` | implements the username-and-password authentication strategy, |
| `magiclink` | `github.com/malcolmston/passport/strategies/magiclink` | implements passwordless "magic link" authentication. A |
| `microsoft` | `github.com/malcolmston/passport/strategies/microsoft` | provides a passport OAuth2 strategy preset for the Microsoft |
| `oauth1` | `github.com/malcolmston/passport/strategies/oauth1` | implements the core of an OAuth 1.0a (RFC 5849) authentication |
| `oauth1twitter` | `github.com/malcolmston/passport/strategies/oauth1twitter` | is a thin wrapper over strategies/oauth1 that presets |
| `oauth2` | `github.com/malcolmston/passport/strategies/oauth2` | implements a generic, testable OAuth2 authorization-code |
| `okta` | `github.com/malcolmston/passport/strategies/okta` | provides a passport OAuth2 strategy preset for Okta. Okta is |
| `openidconnect` | `github.com/malcolmston/passport/strategies/openidconnect` | implements an OpenID Connect (OIDC) authentication |
| `querytoken` | `github.com/malcolmston/passport/strategies/querytoken` | authenticates requests by reading a token from a query |
| `reddit` | `github.com/malcolmston/passport/strategies/reddit` | provides a passport OAuth2 strategy preset for the Reddit |
| `refreshjwt` | `github.com/malcolmston/passport/strategies/refreshjwt` | authenticates a request using a refresh-token JWT carried |
| `refreshtoken` | `github.com/malcolmston/passport/strategies/refreshtoken` | authenticates OAuth2-style refresh-token requests. The |
| `remembercookie` | `github.com/malcolmston/passport/strategies/remembercookie` | implements persistent "remember me" login using the |
| `saml` | `github.com/malcolmston/passport/strategies/saml` | implements a minimal Service Provider handler for a SAML 2.0 |
| `sessionjwt` | `github.com/malcolmston/passport/strategies/sessionjwt` | implements stateless sessions backed by a signed JWT stored |
| `sessiontoken` | `github.com/malcolmston/passport/strategies/sessiontoken` | authenticates requests by reading an opaque session |
| `signedtoken` | `github.com/malcolmston/passport/strategies/signedtoken` | implements self-contained HMAC-signed token |
| `slack` | `github.com/malcolmston/passport/strategies/slack` | provides a passport OAuth2 strategy preset for the Slack |
| `spotify` | `github.com/malcolmston/passport/strategies/spotify` | provides a passport OAuth2 strategy preset for the Spotify |
| `stripe` | `github.com/malcolmston/passport/strategies/stripe` | provides a passport OAuth2 strategy preset for the Stripe |
| `totp` | `github.com/malcolmston/passport/strategies/totp` | implements Time-based One-Time Password (TOTP) authentication as |
| `twitch` | `github.com/malcolmston/passport/strategies/twitch` | provides a passport OAuth2 strategy preset for the Twitch |
| `twitter` | `github.com/malcolmston/passport/strategies/twitter` | provides a passport OAuth2 strategy preset for the Twitter |
| `webauthn` | `github.com/malcolmston/passport/strategies/webauthn` | implements WebAuthn (passkey / FIDO2) authentication for |
| `yandex` | `github.com/malcolmston/passport/strategies/yandex` | provides a passport OAuth2 strategy preset for the Yandex |
