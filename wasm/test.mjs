// Node smoke test: build must be run first (see build.sh). Verifies passport's
// Go token/OTP implementations are reachable from JS through wasm.
import assert from 'node:assert';
import { loadPassport } from './passport.mjs';

const passport = await loadPassport();

// JWT round-trips: sign a claims object, verify it back.
const token = passport.jwtSign({ sub: 'abc', role: 'admin' }, 'top-secret');
assert.strictEqual(token.split('.').length, 3, 'JWT has header.payload.signature');
const claims = passport.jwtVerify(token, 'top-secret');
assert.ok(claims, 'valid token verifies');
assert.strictEqual(claims.sub, 'abc', 'sub claim round-trips');
assert.strictEqual(claims.role, 'admin', 'role claim round-trips');

// A wrong secret must fail verification (returns null).
assert.strictEqual(passport.jwtVerify(token, 'wrong-secret'), null, 'wrong secret rejected');
// A tampered token must fail verification (returns null).
const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
assert.strictEqual(passport.jwtVerify(tampered, 'top-secret'), null, 'tampered token rejected');

// TOTP against the RFC 6238 SHA1 vector: secret "12345678901234567890" in base32.
const totpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
assert.strictEqual(passport.totpGenerate(totpSecret, 59), '287082', 'RFC 6238 vector at t=59');
assert.ok(passport.totpVerify(totpSecret, '287082', 59), 'TOTP verifies its own code');
assert.ok(!passport.totpVerify(totpSecret, '000000', 59), 'wrong TOTP code rejected');

// HOTP against the RFC 4226 vectors for the same base32 secret.
assert.strictEqual(passport.hotpGenerate(totpSecret, 0), '755224', 'RFC 4226 vector at counter 0');
assert.strictEqual(passport.hotpGenerate(totpSecret, 1), '287082', 'RFC 4226 vector at counter 1');

console.log('passport wasm adapter: all JS-side assertions passed');
console.log(`  jwt: {sub:'abc'} -> ${token.slice(0, 24)}... -> verify sub=${claims.sub}`);
process.exit(0);
