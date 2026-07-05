// Command webauthn demonstrates WebAuthn (passkey / FIDO2) authentication end
// to end, including the browser-side ceremonies:
//
//	GET  /                 page with Register / Log in buttons and the JS
//	POST /register/begin   issue PublicKeyCredentialCreationOptions
//	POST /register/finish  store the new credential (attestation)
//	POST /login/begin      issue PublicKeyCredentialRequestOptions
//	POST /login/finish     verify the assertion (the webauthn strategy runs here)
//
// Open http://localhost:3000 in a browser with a platform authenticator.
// WebAuthn requires a secure context; localhost qualifies.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/webauthn"
)

// demoUser is the single account this demo registers passkeys for.
const demoUser = "alice"

// credStore is an in-memory webauthn.Store mapping credential id -> credential
// and its owning user. A real store is database-backed.
type credStore struct {
	mu    sync.Mutex
	creds map[string]*webauthn.Credential // key: string(credentialID)
	owner map[string]string               // key: string(credentialID) -> user
}

func newCredStore() *credStore {
	return &credStore{creds: map[string]*webauthn.Credential{}, owner: map[string]string{}}
}

func (s *credStore) Get(id []byte) (any, *webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.creds[string(id)]
	if !ok {
		return nil, nil, nil
	}
	return s.owner[string(id)], cred, nil
}

func (s *credStore) Put(user string, cred *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[string(cred.ID)] = cred
	s.owner[string(cred.ID)] = user
}

// UpdateSignCount implements webauthn.SignCountUpdater (clone detection).
func (s *credStore) UpdateSignCount(id []byte, n uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.creds[string(id)]; ok {
		c.SignCount = n
	}
	return nil
}

func (s *credStore) idsFor(user string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids [][]byte
	for id, u := range s.owner {
		if u == user {
			ids = append(ids, []byte(id))
		}
	}
	return ids
}

// challengeStore keeps the expected challenge for an in-flight ceremony, keyed
// by a short-lived cookie the begin handlers set.
type challengeStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newChallengeStore() *challengeStore { return &challengeStore{m: map[string][]byte{}} }

func (c *challengeStore) set(id string, challenge []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = challenge
}

func (c *challengeStore) get(id string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[id]
}

const ceremonyCookie = "wa_ceremony"

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>WebAuthn passkey demo</title></head>
<body>
  <h1>Passkey sign in (WebAuthn)</h1>
  <button id="register">Register a passkey</button>
  <button id="login">Log in with passkey</button>
  <pre id="log"></pre>
  <script>
    function log(msg) { document.getElementById('log').textContent += msg + "\n"; }

    // ---- base64url <-> ArrayBuffer helpers (no template literals) ----
    function b64urlToBuf(s) {
      s = s.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) { s += '='; }
      var bin = atob(s);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
      return bytes.buffer;
    }
    function bufToB64url(buf) {
      var bytes = new Uint8Array(buf);
      var bin = '';
      for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function register() {
      var opts = await (await fetch('/register/begin', {method: 'POST'})).json();
      opts.challenge = b64urlToBuf(opts.challenge);
      opts.user.id = b64urlToBuf(opts.user.id);
      var cred = await navigator.credentials.create({publicKey: opts});
      var body = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        attestationObject: bufToB64url(cred.response.attestationObject),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON)
      };
      var r = await fetch('/register/finish', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
      log('register: ' + r.status + ' ' + (await r.text()));
    }

    async function login() {
      var opts = await (await fetch('/login/begin', {method: 'POST'})).json();
      opts.challenge = b64urlToBuf(opts.challenge);
      opts.allowCredentials = (opts.allowCredentials || []).map(function (c) {
        return {type: c.type, id: b64urlToBuf(c.id)};
      });
      var assertion = await navigator.credentials.get({publicKey: opts});
      var body = {
        id: assertion.id,
        rawId: bufToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
          authenticatorData: bufToB64url(assertion.response.authenticatorData),
          signature: bufToB64url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : ''
        }
      };
      var r = await fetch('/login/finish', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
      log('login: ' + r.status + ' ' + (await r.text()));
    }

    document.getElementById('register').onclick = function () { register().catch(function (e) { log('error: ' + e); }); };
    document.getElementById('login').onclick = function () { login().catch(function (e) { log('error: ' + e); }); };
  </script>
</body>
</html>`

// registerFinish mirrors the browser's registration POST body.
type registerFinish struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

func newCeremonyID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	cfg := webauthn.Config{
		RPID:     "localhost",
		RPOrigin: "http://localhost:3000",
		RPName:   "Passport Demo",
	}
	store := newCredStore()
	challenges := newChallengeStore()

	challengeFor := func(r *http.Request) []byte {
		c, err := r.Cookie(ceremonyCookie)
		if err != nil {
			return nil
		}
		return challenges.get(c.Value)
	}

	p := passport.New()
	p.Use(webauthn.New(cfg, store, challengeFor))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	// setCeremony stashes the challenge and sets the ceremony cookie.
	setCeremony := func(w http.ResponseWriter, challenge []byte) {
		id := newCeremonyID()
		challenges.set(id, challenge)
		http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: id, Path: "/", HttpOnly: true})
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()

	// GET / serves the page and browser ceremonies.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	// POST /register/begin — creation options + challenge.
	mux.HandleFunc("/register/begin", func(w http.ResponseWriter, r *http.Request) {
		challenge, options, err := cfg.BeginRegistration(demoUser, demoUser, "Alice")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		setCeremony(w, challenge)
		writeJSON(w, options)
	})

	// POST /register/finish — verify attestation and store the credential.
	mux.HandleFunc("/register/finish", func(w http.ResponseWriter, r *http.Request) {
		var body registerFinish
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		att, err1 := base64.RawURLEncoding.DecodeString(body.AttestationObject)
		cdj, err2 := base64.RawURLEncoding.DecodeString(body.ClientDataJSON)
		if err1 != nil || err2 != nil {
			http.Error(w, "bad encoding", http.StatusBadRequest)
			return
		}
		cred, err := cfg.FinishRegistration(att, cdj, challengeFor(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.Put(demoUser, cred)
		_, _ = w.Write([]byte("passkey registered"))
	})

	// POST /login/begin — request options + challenge, restricted to the
	// user's registered credentials.
	mux.HandleFunc("/login/begin", func(w http.ResponseWriter, r *http.Request) {
		challenge, options, err := cfg.BeginAuthentication(store.idsFor(demoUser))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		setCeremony(w, challenge)
		writeJSON(w, options)
	})

	// POST /login/finish — the webauthn strategy verifies the assertion.
	mux.Handle("/login/finish", p.Authenticate("webauthn")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("authenticated " + passport.User(r).(string)))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000 — open http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", handler))
}
