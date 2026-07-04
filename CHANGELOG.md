# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
