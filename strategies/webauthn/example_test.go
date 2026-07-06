package webauthn_test

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/webauthn"
)

// credStore is a minimal in-memory webauthn.Store: it resolves a credential id
// to the owning user and the stored *webauthn.Credential. A real store is
// backed by a database.
type credStore struct {
	mu    sync.Mutex
	byID  map[string]*webauthn.Credential
	owner map[string]string
}

func (s *credStore) Get(id []byte) (any, *webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.byID[string(id)]
	if !ok {
		return nil, nil, nil
	}
	return s.owner[string(id)], cred, nil
}

// ExampleNew shows the full wiring for WebAuthn (passkey) authentication. The
// login ceremony has two legs: /login/begin issues a fresh challenge with
// BeginAuthentication, and /login/finish receives the browser's assertion, which
// the strategy verifies against the stored credential. The raw challenge produced
// by BeginAuthentication must be stashed per-ceremony (here keyed by a cookie) and
// returned by the ChallengeFunc during verification, or the origin/challenge check
// fails. The credStore resolves the credential id in the assertion to the owning
// user and the persisted *webauthn.Credential. On success passport logs the user
// in, and Chain installs Initialize and Session so later requests restore the user
// from the session cookie.
func ExampleNew() {
	cfg := webauthn.Config{
		RPID:     "localhost",
		RPOrigin: "http://localhost:3000",
		RPName:   "Passport Demo",
	}
	store := &credStore{byID: map[string]*webauthn.Credential{}, owner: map[string]string{}}

	// challenges maps a per-ceremony cookie value to the expected challenge.
	var mu sync.Mutex
	challenges := map[string][]byte{}
	challengeFor := func(r *http.Request) []byte {
		c, err := r.Cookie("wa_ceremony")
		if err != nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		return challenges[c.Value]
	}

	p := passport.New()
	p.Use(webauthn.New(cfg, store, challengeFor))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// POST /login/begin — issue a challenge for the assertion ceremony.
	mux.HandleFunc("/login/begin", func(w http.ResponseWriter, r *http.Request) {
		challenge, _, err := cfg.BeginAuthentication(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		challenges["ceremony-id"] = challenge
		mu.Unlock()
		// Return the options JSON to the browser (omitted here for brevity).
	})

	// POST /login/finish — the browser's assertion; the strategy verifies it.
	mux.Handle("/login/finish", p.Authenticate("webauthn")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("authenticated " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// Example_frontend shows the browser half of the passkey login ceremony. The
// page fetches request options from /login/begin, hands them to
// navigator.credentials.get(), and POSTs the resulting assertion to
// /login/finish where the strategy verifies it. Binary fields returned by the
// browser (rawId, clientDataJSON, authenticatorData, signature) are base64url-
// encoded before being sent, because that is the shape the strategy decodes. The
// server-provided challenge must be converted from base64url into an ArrayBuffer
// for the WebAuthn API, and the credential id likewise. The commented create()
// call sketches the registration ceremony, which mirrors this flow using the
// options from BeginRegistration and a POST to a /register/finish route.
func Example_frontend() {
	http.HandleFunc("/passkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>Sign in with a passkey</title>
<button id="login">Sign in with a passkey</button>
<pre id="out"></pre>
<script>
  const b64urlToBuf = s =>
    Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const bufToB64url = b =>
    btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  document.getElementById("login").addEventListener("click", async () => {
    // 1. Ask the server for request options (includes the challenge).
    const opts = await (await fetch("/login/begin", { method: "POST" })).json();
    opts.challenge = b64urlToBuf(opts.challenge);
    for (const c of opts.allowCredentials || []) c.id = b64urlToBuf(c.id);

    // 2. Let the authenticator produce an assertion.
    const cred = await navigator.credentials.get({ publicKey: opts });

    // 3. Send the assertion back for verification.
    const res = await fetch("/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature: bufToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : "",
        },
      }),
    });
    document.getElementById("out").textContent = await res.text();
  });

  // Registration is the mirror image: fetch options from a /register/begin
  // route, call navigator.credentials.create({ publicKey: opts }), and POST the
  // attestation to a route backed by Config.FinishRegistration.
</script>`)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}
