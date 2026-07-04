// Idiomatic JS wrapper around the passport WebAssembly adapter.
//
//   import { loadPassport } from './passport.mjs';
//   const passport = await loadPassport();          // browser (fetch) or Node
//   const token = passport.jwtSign({ sub: 'abc' }, 'secret');
//   const claims = passport.jwtVerify(token, 'secret');   // { sub: 'abc' } | null
//   passport.totpGenerate('GEZDGNBVGY3TQOJQ');            // 6-digit code
//
// Only passport's portable, pure token/OTP utilities are exposed; the net/http
// Strategy middleware stays in Go. The same Go implementation runs here via wasm.

async function ensureGo() {
  if (typeof globalThis.Go === 'function') return;
  if (typeof window === 'undefined') {
    // Node: wasm_exec.js is a classic script that assigns globalThis.Go.
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const path = fileURLToPath(new URL('./wasm_exec.js', import.meta.url));
    const { runInThisContext } = await import('node:vm');
    runInThisContext(readFileSync(path, 'utf8'));
  } else {
    await import('./wasm_exec.js');
  }
}

async function readWasm(wasmPath) {
  if (typeof window === 'undefined') {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const p = wasmPath ?? fileURLToPath(new URL('./passport.wasm', import.meta.url));
    return readFileSync(p);
  }
  const res = await fetch(wasmPath ?? new URL('./passport.wasm', import.meta.url));
  return new Uint8Array(await res.arrayBuffer());
}

export async function loadPassport(wasmPath) {
  await ensureGo();
  const go = new globalThis.Go();
  const bytes = await readWasm(wasmPath);
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(instance); // long-running; resolves when the module exits (it won't)
  const g = globalThis.__mgo_passport;
  if (!g) throw new Error('passport wasm did not register __mgo_passport');

  return {
    // JWT (HS256): sign a claims object, verify a token back to claims (or null).
    jwtSign: (claims, secret) => g.jwtSign(claims ?? {}, String(secret)),
    jwtVerify: (token, secret) => g.jwtVerify(String(token), String(secret)),
    // TOTP (RFC 6238) over a base32 secret; unixSeconds defaults to now.
    totpGenerate: (secret, unixSeconds) =>
      unixSeconds === undefined
        ? g.totpGenerate(String(secret))
        : g.totpGenerate(String(secret), Number(unixSeconds)),
    totpVerify: (secret, code, unixSeconds) =>
      unixSeconds === undefined
        ? g.totpVerify(String(secret), String(code))
        : g.totpVerify(String(secret), String(code), Number(unixSeconds)),
    // HOTP (RFC 4226) over a base32 secret and counter.
    hotpGenerate: (secret, counter) => g.hotpGenerate(String(secret), Number(counter)),
  };
}
