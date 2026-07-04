// Library content for the Passport-for-Go documentation site. The `passport`
// entry is copied verbatim from the aggregate malcolmston/go landing site's
// data so the two stay in sync.
export interface Lib {
  id: string; name: string; icon: string; accent: string; pkg: string; node: string;
  repo: string; docs: string; tagline: string; blurb: string; tags: string[];
  features: string[]; node_code: string; go_code: string; integrate: string;
}

export const NODE_ACCENT = '#8cc84b';

export const LIB: Lib = {
  id: "passport", name: "Passport", icon: '<i class="fa-solid fa-shield-halved"></i>', accent: "#7ee787",
  pkg: "github.com/malcolmston/passport", node: "jaredhanson/passport",
  repo: "https://github.com/malcolmston/passport", docs: "https://malcolmston.github.io/passport/",
  tagline: "Simple, unobtrusive authentication.",
  blurb: "A strategy-based auth middleware for net/http. 100+ strategies — local, basic, bearer, JWT, OAuth2 with " +
    "60+ providers, WebAuthn passkeys, and OpenID Connect with RS256/JWKS — plus session serialize/deserialize.",
  tags: ["100+ strategies", "OAuth2", "WebAuthn", "JWT / JWKS", "OIDC", "sessions"],
  features: [
    "Strategy interface with <code>Success / Fail / Redirect / Error / Pass</code>",
    "Local, Basic, Bearer, API-key, HMAC, TOTP/HOTP, magic-link, client-cert …",
    "OAuth2 base + 60+ providers: Google, GitHub, Facebook, Slack, Discord, Apple …",
    "OpenID Connect id_tokens verified via <b>RS256/ES256 JWKS</b> (Google, Auth0, Okta, Azure)",
    "WebAuthn / passkeys (CBOR + COSE, ES256/RS256 assertions)",
    "Session <code>SerializeUser</code> / <code>DeserializeUser</code>, pluggable <code>Store</code>",
    "<code>RequireLogin</code> gate, custom callbacks, multi-strategy, <code>passReq</code>"
  ],
  node_code:
`const passport = require('passport')
const { Strategy } = require('passport-local')

passport.use(new Strategy((user, pw, done) => {
  if (user === 'alice' && pw === 'password123')
    return done(null, { id: '1', name: 'Alice' })
  return done(null, false)
}))`,
  go_code:
`p := passport.New()

p.Use(local.New(func(user, pw string) (any, error) {
    if user == "alice" && pw == "password123" {
        return User{ID: "1", Name: "Alice"}, nil
    }
    return nil, local.ErrInvalidCredentials
}))`,
  integrate:
`<span class="tok-c">// Sessions + a guarded route</span>
p.SerializeUser(func(u any) (string, error) { return u.(User).ID, nil })
p.DeserializeUser(func(id string, r *http.Request) (any, error) {
    return lookupUserByID(id), nil
})

mux := http.NewServeMux()
mux.Handle("/login", p.Authenticate("local")(welcomeHandler))
mux.Handle("/profile", p.RequireLogin("/login")(profileHandler))

handler := passport.Chain(mux, p.Initialize(), p.Session())
http.ListenAndServe(":3000", handler)`
};
