# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-11
### Security
- **HTTP Digest `uri` is bound to the request target (GHSA-p8f3-4jp3-4pp2, high).**
  The `uri` field was hashed into the response digest but never compared with the
  actual request path, so one captured header authenticated every route reachable
  by the same method. Mismatches now return 400.
- **`WWW-Authenticate` is emitted only for genuine HTTP-auth challenges.** The
  local strategy leaked a challenge header on failure.
- Basic and Digest now distinguish 400 (malformed header) from 401
  (missing/rejected credentials), matching upstream.

### Changed
- Measured parity against Passport.js raised from 66.2% to 100% of compared cases
  (72/74), plus nested `httpauth`, `pkce`, `otpauth` and `pwhash` harnesses at
  100%. Four further fixes where the port accepted input the RFC rejects: a
  realm-less digest credential, HTAB as a scheme separator, a non-base32 OTP
  secret, and an `otpauth://hotp/` URI with no counter.

### Breaking
- `Options.Session` is now `*bool` (nil = enabled, matching Passport's
  `session: true` default). Previously the Go zero value silently disabled the
  session, so `Options{SuccessRedirect: "/"}` logged nobody in. Use `NoSession()`
  to opt out.
### Fixed
- Cross-language parity with upstream `passport` / `passport-http` /
  `passport-http-bearer` (harness `parity/passport/`) raised from 66.2% to 100%
  of compared cases (2 documented deviations, see `API-DEVIATIONS.md`):
  - `Options.Session` is now a `*bool` (three states: nil = default-on matching
    Passport.js `session:true`, `*false` = stateless, `*true` = explicit).
    Previously the Go `bool` zero value meant `Options{SuccessRedirect: "/"}`
    silently disabled the session, so the idiomatic upstream login never
    established one. Use `NoSession()` / `WithSession()` helpers.
  - HTTP Digest now enforces the RFC 7616 `uri` binding: the client's `uri`
    directive must equal the request target, else 400 — a captured header no
    longer authenticates a different path (matches upstream's
    `req.url !== creds.uri` check).
  - HTTP Basic and Digest now return 400 (no challenge) for a syntactically
    malformed `Authorization` header, and 401 + challenge only for a
    missing/rejected credential, matching upstream's two rejection modes.
  - `WWW-Authenticate` is emitted only for genuine HTTP-auth challenges
    (new `Context.FailWithChallenge`) on a 401 — the local strategy no longer
    leaks `WWW-Authenticate: Invalid credentials` / `Missing credentials`.
  - The local strategy no longer misclassifies a present, non-string JSON
    password as a missing credential (400); it now fails authentication (401)
    without coercing the value into a possible match.
  - The Digest challenge header field order now matches upstream byte-for-byte
    (`realm, nonce, qop`).
### Added
- `passport.Context.FailWithChallenge` — records an authentication failure whose
  challenge is emitted as a `WWW-Authenticate` header (as distinct from `Fail`,
  whose challenge is a plain message).
- `passport.NoSession()` / `passport.WithSession()` — helpers for the new
  `Options.Session *bool`.


## [0.3.0] - 2026-07-18
### Added
- OAuth2 parity primitives that the `strategies/oauth2` base deliberately
  omitted:
  - `pkce` — Proof Key for Code Exchange (RFC 7636): verifier generation, S256
    and plain challenge derivation, and constant-time verification, validated
    against the RFC 7636 Appendix B vector.
  - `oauthstate` — CSRF "state" handling with a single-use server-side
    `MemoryStore` and a stateless HMAC-signed `HMACStore`, both satisfying a
    common `Store` interface.
  - `scope` — an insertion-ordered `Set` for parsing, comparing, and combining
    space-delimited OAuth scope strings.
- `pwhash` — PBKDF2 (RFC 2898) password hashing and verification with a
  self-describing Django-style encoding, validated against the RFC 6070 vectors
  (HMAC-SHA1) and a known HMAC-SHA256 vector.
- `otpauth` — build and parse `otpauth://` key URIs (Google Authenticator Key
  Uri Format) for provisioning TOTP/HOTP secrets, complementing the existing
  `totp`/`hotp` strategies.
- `token` — crypto/rand-backed opaque token generation (hex, base64url, numeric)
  and constant-time comparison, shared by the bearer/API-key/magic-link
  strategies.
- `httpauth` — exact encode/decode of HTTP `Basic` (RFC 7617) and `Bearer`
  (RFC 6750) `Authorization` headers plus `WWW-Authenticate` challenge builders,
  validated against the RFC 7617 example.
- 50 new OAuth2 provider presets toward catalog parity with Passport.js: yahoo,
  battlenet, vimeo, soundcloud, tiktok, uber, unsplash, orcid, zoho, intuit,
  xero, gitee, osu, epicgames, openstreetmap, buffer, calendly, typeform,
  airtable, webflow, canva, linear, miro, mailru, wechat, weibo, sentry, medium,
  snapchat, oura, bitly, wakatime, dailymotion, deviantart, smartsheet,
  freshbooks, producthunt, nightbot, bungie, ebay, mercadolibre, streamlabs,
  webex, pipedrive, surveymonkey, adobe, whoop, feedly, trakt, and arcgis.

## [0.1.0] - 2026-07-04
### Added
- Initial public release — a strategy-based authentication middleware for
  `net/http`, a faithful Go port of Passport.
- 100+ strategies: local, basic, bearer, API-key, HMAC, TOTP/HOTP, magic-link,
  client-certificate, and more.
- OAuth2 base plus 60+ providers (Google, GitHub, Facebook, Slack, Discord,
  Apple, GitLab, …).
- OpenID Connect id_tokens verified via RS256/ES256 JWKS (Google, Auth0, Okta,
  Azure AD).
- WebAuthn / passkeys (CBOR + COSE, ES256/RS256 assertions).
- Session `SerializeUser` / `DeserializeUser` with a pluggable `Store`,
  `RequireLogin` gate, custom callbacks, multi-strategy, and `passReq`.
- Shared `Strategy` / `Named` / `Authenticator` / `OAuth2Provider` interfaces.
- `TestStrategyPackagesAreCompliant` runner — every `strategies/<name>` package
  must expose a Strategy (`Name` + `Authenticate`) and ship at least one test.
- Automated releases (VERSION-driven tags + GitHub Releases, moving `stable` tag).
- CI: build/test matrix (Go 1.23 & 1.24), `-race` + coverage, golangci-lint v2,
  govulncheck, CodeQL, benchmarks, dependency review, and a stale bot.

[Unreleased]: https://github.com/malcolmston/passport/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/malcolmston/passport/releases/tag/v0.1.0
