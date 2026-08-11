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
