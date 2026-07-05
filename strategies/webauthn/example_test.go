package webauthn_test

import (
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

// ExampleNew shows the full wiring for WebAuthn (passkey) authentication: the
// login ceremony's assertion is POSTed to /login/finish, where the strategy
// verifies it against the stored credential. The challenge produced by
// BeginAuthentication must be stashed per-user (here, keyed by a cookie) and
// returned by the ChallengeFunc during verification.
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
