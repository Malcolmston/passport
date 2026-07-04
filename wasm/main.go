//go:build js && wasm

// Command passport (wasm) exposes passport's portable, pure token/OTP utilities
// to JavaScript. Built with GOOS=js GOARCH=wasm it registers a `__mgo_passport`
// object on the JS global so the very same Go implementations — JWT (HS256)
// signing/verification and RFC 6238/4226 TOTP/HOTP code generation — run in Go
// and in the browser or Node. The net/http Strategy middleware is deliberately
// NOT exposed: it has no meaning outside a server. See passport.mjs for the
// idiomatic JS wrapper.
package main

import (
	"encoding/base32"
	"encoding/json"
	"strings"
	"syscall/js"
	"time"

	"github.com/malcolmston/passport/strategies/hotp"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/totp"
)

func main() {
	obj := js.Global().Get("Object").New()
	obj.Set("jwtSign", js.FuncOf(jwtSignFn))
	obj.Set("jwtVerify", js.FuncOf(jwtVerifyFn))
	obj.Set("totpGenerate", js.FuncOf(totpGenerateFn))
	obj.Set("totpVerify", js.FuncOf(totpVerifyFn))
	obj.Set("hotpGenerate", js.FuncOf(hotpGenerateFn))
	js.Global().Set("__mgo_passport", obj)

	select {} // keep the Go runtime alive so the exported funcs stay callable
}

// jwtSign(claims, secret) signs an HS256 JWT for the given claims object and
// secret string, returning the compact token. Returns null on error.
func jwtSignFn(_ js.Value, a []js.Value) any {
	if len(a) < 2 || a[0].Type() != js.TypeObject {
		return nil
	}
	jsonStr := js.Global().Get("JSON").Call("stringify", a[0]).String()
	var claims jwt.Claims
	if err := json.Unmarshal([]byte(jsonStr), &claims); err != nil {
		return nil
	}
	tok, err := jwt.Sign([]byte(a[1].String()), claims)
	if err != nil {
		return nil
	}
	return tok
}

// jwtVerify(token, secret) verifies a token's HS256 signature and time claims,
// returning the decoded claims as a JS object, or null if verification fails.
func jwtVerifyFn(_ js.Value, a []js.Value) any {
	if len(a) < 2 {
		return nil
	}
	s := &jwt.Strategy{Secret: []byte(a[1].String())}
	claims, err := s.Parse(a[0].String())
	if err != nil {
		return nil
	}
	out, err := json.Marshal(claims)
	if err != nil {
		return nil
	}
	return js.Global().Get("JSON").Call("parse", string(out))
}

// totpGenerate(secret[, unixSeconds]) returns the RFC 6238 TOTP code for the
// base32 secret at the given Unix time (defaults to now). Returns null if the
// secret is not valid base32.
func totpGenerateFn(_ js.Value, a []js.Value) any {
	if len(a) < 1 {
		return nil
	}
	secret, ok := decodeBase32(a[0].String())
	if !ok {
		return nil
	}
	t := time.Now()
	if len(a) > 1 && a[1].Type() == js.TypeNumber {
		t = time.Unix(int64(a[1].Float()), 0)
	}
	return totp.Generate(secret, t)
}

// totpVerify(secret, code[, unixSeconds]) reports whether code matches the TOTP
// value for the base32 secret within ±1 time step (the package default skew) of
// the given Unix time (defaults to now).
func totpVerifyFn(_ js.Value, a []js.Value) any {
	if len(a) < 2 {
		return false
	}
	secret, ok := decodeBase32(a[0].String())
	if !ok {
		return false
	}
	code := a[1].String()
	t := time.Now()
	if len(a) > 2 && a[2].Type() == js.TypeNumber {
		t = time.Unix(int64(a[2].Float()), 0)
	}
	for i := -1; i <= 1; i++ {
		if totp.Generate(secret, t.Add(time.Duration(i)*totp.Step)) == code {
			return true
		}
	}
	return false
}

// hotpGenerate(secret, counter) returns the RFC 4226 HOTP code for the base32
// secret and counter. Returns null if the secret is not valid base32.
func hotpGenerateFn(_ js.Value, a []js.Value) any {
	if len(a) < 2 {
		return nil
	}
	secret, ok := decodeBase32(a[0].String())
	if !ok {
		return nil
	}
	return hotp.Generate(secret, uint64(a[1].Float()))
}

// decodeBase32 decodes an authenticator-style base32 secret, tolerating
// lowercase, spaces, and optional padding.
func decodeBase32(s string) ([]byte, bool) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	s = strings.TrimRight(s, "=")
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}
