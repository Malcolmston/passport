# Backlog — missing strategies & features

Curated real work for this Passport port. Passport.js has 500+ community
strategies; this lists the notable ones not yet ported plus core feature gaps.
(See the note at the bottom about the "10,000" target.)

## Core feature gaps

- [ ] `passReqToCallback` for every strategy (only `local` has `NewWithRequest`).
- [ ] `authInfo` transform + `req.authInfo`.
- [ ] `successFlash` / `failureFlash` (connect-flash integration).
- [ ] `assignProperty` (custom `req.user` property), `keepSessionInfo`.
- [ ] `failWithError`, `failureMessage` session storage.
- [ ] Strategy-scoped serialize/deserialize; multiple user models.
- [ ] Full OIDC: RS256/ES256 + JWKS discovery, `nonce`, PKCE, `state` binding,
      userinfo, back-channel logout, discovery document parsing.
- [ ] OAuth2 PKCE, token refresh helpers, `state` store, scope validation.
- [ ] OAuth1 request-token-secret session storage for the full 3-legged flow.
- [ ] SAML: signature validation, encrypted assertions, metadata, SLO, replay
      protection (currently parse-only).
- [ ] WebAuthn: RS256 already supported; add EdDSA (Ed25519), attestation
      statement verification (packed/tpm/android-key/fido-u2f), resident keys,
      user-verification policy, and a credential-store helper.
- [ ] LDAP: real network bind (currently delegated), TLS, search filters.

## Ecosystem strategies not yet ported

OAuth/OIDC providers:

- [ ] passport-42, passport-amazon, passport-arcgis, passport-atlassian-oauth2
- [ ] passport-azure-ad / azuread-openidconnect, passport-battlenet
- [ ] passport-box, passport-coinbase, passport-digitalocean
- [ ] passport-dropbox-oauth2, passport-eveonline, passport-facebook-token
- [ ] passport-fitbit-oauth2, passport-flickr, passport-foursquare
- [ ] passport-freshbooks, passport-github (v1), passport-google-oauth (v1)
- [ ] passport-goodreads, passport-hubspot, passport-imgur, passport-instagram
- [ ] passport-intuit-oauth, passport-jira, passport-kakao, passport-keycloak
- [ ] passport-line, passport-linkedin (v1), passport-magento, passport-mailchimp
- [ ] passport-mastodon, passport-medium, passport-meetup, passport-mixcloud
- [ ] passport-naver, passport-notion, passport-odnoklassniki, passport-onelogin
- [ ] passport-openstreetmap, passport-patreon, passport-paypal-oauth
- [ ] passport-pinterest, passport-pocket, passport-quickbooks, passport-salesforce
- [ ] passport-shopify, passport-slack (bot scopes), passport-snapchat
- [ ] passport-soundcloud, passport-spotify (v1), passport-square
- [ ] passport-stackexchange, passport-steam, passport-strava-oauth2
- [ ] passport-trello, passport-tumblr, passport-twitch-new, passport-uber
- [ ] passport-vkontakte, passport-wechat, passport-weibo, passport-windowslive
- [ ] passport-wordpress, passport-xero, passport-yahoo-oauth2, passport-yammer
- [ ] passport-zendesk, passport-zoom

Non-OAuth mechanisms:

- [ ] passport-http (Digest full RFC 7616 with qop/nonce-count/opaque)
- [ ] passport-http-bearer scopes, passport-oauth2-client-password
- [ ] passport-anonymous chaining, passport-custom
- [ ] passport-ldapauth, passport-activedirectory, passport-kerberos, passport-ntlm
- [ ] passport-saml, passport-wsfed-saml2, passport-cas (proxy tickets)
- [ ] passport-fido2-webauthn, passport-u2f
- [ ] passport-totp (with issuer), passport-hotp, passport-otp
- [ ] passport-magic-login, passport-magic (Magic.link), passport-passwordless
- [ ] passport-jwt (RS256/ES256 + JWKS), passport-azure-ad-jwt
- [ ] passport-apikey (variants), passport-headerapikey, passport-unique-token
- [ ] passport-token, passport-accesstoken, passport-client-cert (chain verify)
- [ ] passport-google-id-token (RS256 via Google certs), passport-firebase-jwt
- [ ] passport-auth0, passport-okta-oauth, passport-cognito-oauth2
- [ ] passport-saml-metadata, passport-trusted-header
- [ ] passport-web3 / sign-in-with-ethereum (SIWE)
- [ ] passport-apple (client-secret JWT signing with ES256)

## Testing / tooling

- [ ] JWKS test fixtures + RS256/ES256 cross-verification with Node `jose`.
- [ ] Interop tests for OAuth2 flow against a Node `passport-oauth2` server.
- [ ] Fuzz the CBOR decoder (webauthn) and JWT parser.
- [ ] `golangci-lint` config; race tests for the session store.

---

### On the "10,000 items" request

Passport's real strength-in-numbers is its strategy ecosystem — genuinely
hundreds of packages, each a real port. This file names the notable ones rather
than padding to an arbitrary 10,000 with synthetic entries. I can expand this
into the full ecosystem list (500+) on request.
