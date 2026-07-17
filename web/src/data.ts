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
  tagline: "Simple, unobtrusive authentication for net/http.",
  blurb: "A strategy-based authentication middleware for net/http, ported from Passport.js. 104 interchangeable " +
    "strategies — local, basic, bearer, API-key, JWT/JWKS, TOTP/HOTP, magic-link, WebAuthn passkeys, SAML, OpenID " +
    "Connect, and OAuth 2.0 across 67 providers — behind one small Strategy contract. Session " +
    "SerializeUser/DeserializeUser with a pluggable Store, or run stateless. Standard library only, no dependencies.",
  tags: ["104 strategies", "OAuth 2.0", "67 providers", "WebAuthn", "JWT / JWKS", "OIDC", "SAML", "sessions", "stdlib-only"],
  features: [
    "Small <code>Strategy</code> contract: report <code>Success</code> / <code>Fail</code> / <code>Redirect</code> / <code>Error</code> / <code>Pass</code> on a <code>*Context</code>",
    "Credentials: <code>local</code>, <code>basic</code>, <code>digest</code>, <code>bearer</code>, <code>apikey</code>, <code>hmac</code>, <code>clientcert</code>, <code>ldap</code>, <code>cas</code>",
    "One-time &amp; tokenized: <code>totp</code>, <code>hotp</code>, <code>magiclink</code>, <code>jwt</code>, <code>jwtbearer</code>, <code>signedtoken</code>, <code>remembercookie</code>",
    "OAuth 2.0 base plus 67 providers — <code>google</code>, <code>github</code>, <code>facebook</code>, <code>slack</code>, <code>discord</code>, <code>apple</code>, <code>microsoft</code> …",
    "OpenID Connect id_tokens verified against rotating <b>RS256/ES256 JWKS</b> — <code>auth0</code>, <code>okta</code>, <code>azuread</code>, <code>cognito</code>",
    "WebAuthn / passkeys with stdlib CBOR + COSE (ES256/RS256 assertions), plus <code>saml</code> and <code>openidconnect</code>",
    "Sessions via <code>SerializeUser</code> / <code>DeserializeUser</code> and a pluggable <code>Store</code> (<code>MemoryStore</code> default), or <code>Options{Session:false}</code> for stateless APIs",
    "<code>Authenticate</code> / <code>RequireLogin</code> guards, <code>AuthenticateCallback</code>, <code>AuthenticateAny</code> multi-strategy, request-aware <code>custom.New</code> verifiers",
    "Familiar Passport.js API — <code>Use</code>, <code>LogIn</code> / <code>LogOut</code>, <code>User</code>, <code>IsAuthenticated</code> — standard library only"
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
