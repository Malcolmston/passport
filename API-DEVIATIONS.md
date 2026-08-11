# API deviations from Passport.js

This port aims for behavioural parity with `passport` and its official
strategies (`passport-local`, `passport-http`, `passport-http-bearer`), measured
by the cross-language parity harness in the aggregator repo
(`parity/passport/`). Where the port deliberately differs from upstream — and
the difference is intentional rather than a bug — it is recorded here and marked
as a `"deviation"` on the corresponding parity case, so the harness counts it
separately from a mismatch.

Only genuinely deliberate differences belong here. A difference that is simply a
port bug is fixed, not documented.

## 1. HTTP Digest derives HA1 from the server's realm, not the client's

- **Parity case:** `digest-wrong-realm` (group `digest`).
- **Upstream:** `passport-http`'s `DigestStrategy` computes
  `HA1 = MD5(username : creds.realm : password)` using **`creds.realm`** — the
  realm value taken from the client's `Authorization` header. A response
  computed under a client-chosen `realm="Wrong"` therefore **authenticates**.
- **This port:** `digest.Strategy` computes `HA1` using its **own configured
  realm** (`Options.Realm`). A response computed under any realm other than the
  server's is **rejected** with a 401 challenge.
- **Why the port diverges:** trusting an attacker-supplied realm to key the
  password hash weakens the protection space binding that the realm exists to
  provide. The port is deliberately the stricter of the two; matching upstream
  would mean re-introducing an upstream weakness. Both sides still reject a
  wrong *password*; the disagreement is only over a wrong *realm*.

## 2. Logout expires the session cookie instead of regenerating the session

- **Parity case:** `session-logout-revokes` (group `session`).
- **Upstream:** `req.logout` with express-session's `keepSessionInfo:false`
  regenerates the session, which issues a **fresh, empty session cookie** for
  the now-anonymous request (`Set-Cookie` present on the logout response).
- **This port:** `Passport.LogOut` destroys the session server-side and
  **expires** the client cookie (`MaxAge < 0`, empty value); it does not mint a
  new session for an unauthenticated user, so no new session cookie is issued.
- **Why the port diverges:** handing an anonymous client a brand-new session
  cookie it never asked for is unnecessary; expiring the old cookie and dropping
  the server-side record is a cleaner logout. Crucially this is **not** a
  security difference: both implementations invalidate the old session id, so a
  replayed pre-logout cookie authenticates on neither side (the follow-up
  protected request is 401 on both). The port's behaviour is pinned by
  `TestLogOutDestroysSessionAndCookie` and
  `TestLogOutThenTouchSessionDoesNotResurrect`.

---

# Nested-package deviations

The sections above concern the top-level `passport` port, whose oracle is
`passport@0.7.0` and its official strategies. Several nested packages are ports
of *different* upstream projects and have their own harnesses under
`parity/passport/nested/<pkg>/` in the aggregator repo, each with its own
oracle. Their deliberate differences are recorded below, one section per
package, and marked `"deviation"` on the corresponding case.

Every nested harness currently scores **100% on the cases it compares**, and
**none of them has a security finding**: in every deviation below, the port is
the stricter side — it refuses a credential, a key or a parameter set that
upstream accepts — except where the difference is purely cosmetic (parameter
order, percent-encoding).

## 3. `httpauth` — 31 deviations against `http-auth-utils@7.0.1`

Harness: `parity/passport/nested/httpauth/`. Four families:

1. **Quoting is hardened (7 cases:** `basic-challenge-quote-in-realm`,
   `basic-challenge-crlf-in-realm`, `basic-challenge-backslash-in-realm`,
   `bearer-challenge-quote-in-realm`, `bearer-challenge-crlf-in-realm`,
   `dc-quote-in-realm`, `dc-crlf-in-nonce`**).** `httpauth.QuoteString` renders
   caller-supplied realms and nonces as RFC 7230 quoted-strings — escaping `"`
   and `\`, dropping control characters — so neither can terminate the header
   value or split the response. Upstream interpolates them raw. Copying upstream
   would import a header-injection bug.
2. **RFC 7616 rather than RFC 2617 (11 cases:** `dr-md5-sess`,
   `dr-sha256-sess`, `dr-auth-int-with-body`, `dr-rfc2069-no-qop`,
   `dc-charset`, `dc-userhash`, `dc-stale`, `dc-with-domain`,
   `digest-parse-extension-param`, `digest-parse-empty-response-value`,
   `dv-response-empty`**).** The port implements the current Digest RFC:
   `-sess` algorithms, `qop=auth-int` (which hashes the entity body into HA2),
   the qop-less RFC 2069 form, the `charset` and `userhash` parameters,
   extension auth-params, and an unquoted boolean `stale`. Upstream implements
   the 1999 parameter set and either drops or mis-renders these.
3. **Grammar strictness (7 cases:** `basic-parse-uppercase-scheme`,
   `bearer-parse-mixed-case-scheme`, `basic-parse-no-colon`,
   `basic-parse-invalid-base64`, `bearer-parse-extra-space`,
   `digest-parse-spaces-around-equals`, `digest-parse-escaped-quote-in-realm`,
   `scheme-of-unknown-scheme`**).** The scheme token is case-insensitive
   (RFC 7235 §2.1); BWS is allowed around `=` (RFC 7230); a quoted-pair inside a
   quoted-string is unescaped; a Basic payload with no `:` or with invalid
   base64 is rejected rather than turned into a garbage username; a surplus SP
   is not part of a bearer token. Upstream's own source calls its parser a
   "FIXME: Create a real parser".
4. **Renderers do not validate (6 cases:** `bearer-encode-empty-token`,
   `bearer-challenge-unknown-error-code`, `dc-empty-realm`, `dc-missing-nonce`,
   plus the two ordering/quoting cases counted above**).** `Encode*` and
   `*Challenge` are pure formatters: they omit what they were not given and
   accept any RFC 6750 error code (the registry is extensible). Upstream's
   builders throw on a missing required key or an unlisted error code. No
   credential decision is taken on either side.

One further case deserves naming because it looks like a security divergence and
is not:

- **`dv-response-uppercase-hex`.** `httpauth.VerifyDigest` lower-cases both
  digests before its constant-time comparison, because clients disagree about hex
  case; upstream compares the exact string, so the port accepts a credential
  upstream rejects. This is **not** a bypass: case-folding hex is a 1:1
  relabelling of the same digest value, so it admits nobody who does not already
  hold the correct response. Verified against `httpauth/digest.go` before being
  labelled a deviation.

## 4. `pkce` — 7 deviations against `pkce-challenge@6.0.0`

Harness: `parity/passport/nested/pkce/`. All seven share one root cause and all
seven have the port refusing what upstream accepts.

`verifyChallenge` re-derives the challenge and compares strings; it validates
nothing about the verifier. RFC 7636 §4.1 fixes the verifier at 43–128
characters from the unreserved set `[A-Za-z0-9-._~]`, and §4.6 requires the
server to validate what it receives, so `pkce.Verify` checks
`ValidVerifier` first: `vf-plain-both-empty`, `vf-s256-verifier-empty`,
`vf-s256-verifier-too-short`, `vf-plain-too-short`,
`vf-s256-verifier-too-long`, `vf-s256-verifier-bad-charset`,
`vf-s256-verifier-unicode`.

`vf-plain-both-empty` is the one that matters: under the `plain` transformation
the challenge *is* the verifier, so upstream reports a match for an empty
verifier against an empty stored challenge and PKCE stops protecting anything.
The port rejects an empty challenge outright.

## 5. `otpauth` — 8 deviations against `otpauth@9.5.1` (npm)

Harness: `parity/passport/nested/otpauth/`.

1. **Digit bounds (3:** `parse-digits-too-many`, `usable-digits-12`,
   `usable-digits-1`**).** RFC 4226 §5.3 puts a code at 6–8 digits; the port
   allows 6–10 (the widest a 31-bit truncated HOTP value fills) and refuses
   anything else. Upstream accepts any count, including a **1-digit** code whose
   entire search space is ten values.
2. **Degenerate keys (2:** `usable-empty-secret`, `usable-period-negative`**).**
   Upstream generates codes from an empty shared secret (HMAC with an empty key —
   anyone can compute the code) and from a non-positive period.
   `otpauth.Key.Validate` refuses both.
3. **HOTP window is forward-only (1:** `verify-hotp-behind-counter`**).**
   Upstream's HOTP window is symmetric, so a code for an **already consumed**
   counter verifies (`delta: -2`). The port only looks forward, which is what
   makes a consumed counter unreplayable and what RFC 4226 §7.4's "move the
   counter forward on success" is for.
4. **Label percent-encoding (2:** `url-totp-email-account`,
   `url-totp-ampersand-in-issuer`**).** Upstream runs the label through
   `encodeURIComponent` (`@` → `%40`, `&` → `%26`); `Key.URL` escapes only what
   the RFC 3986 path grammar requires. The URIs are equivalent and each side
   parses the other's form (`parse-totp-encoded-label`). Cosmetic.

## 6. `pwhash` — 5 deviations against `pbkdf2@3.1.6`

Harness: `parity/passport/nested/pwhash/`.

1. **Degenerate raw-KDF parameters (4:** `key-iterations-zero`,
   `key-iterations-negative`, `key-length-zero`, `key-length-negative`**).**
   `pwhash.Key` has no error return, matching the signature Go's PBKDF2 has
   always carried (`golang.org/x/crypto/pbkdf2.Key`): an iteration count below 1
   becomes 1 — the RFC 2898 minimum, never fewer — and a non-positive key length
   yields an empty key, where upstream throws. This is reachable only through the
   raw KDF; the credential path rejects both, which `verify-iterations-zero` and
   `verify-iterations-negative` show by failing on *both* sides.
2. **Empty salt in a stored hash (1:** `verify-empty-salt`**).** `pwhash.Decode`
   refuses a stored hash whose salt is empty: `HashWithParams` cannot produce
   one, so it means corruption or tampering, and an unsalted hash is what
   salting exists to prevent. Upstream has no encoded form and no such check.
