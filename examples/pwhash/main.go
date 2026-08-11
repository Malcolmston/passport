// Command pwhash demonstrates the *correct* way to store credentials behind
// the local strategy: never keep the plaintext password, keep a PBKDF2 hash
// produced by the pwhash package and check submitted passwords against it.
//
// The other examples in this directory carry a "real code would hash the
// password" comment on their in-memory user table. This one is that real code.
// It also shows the credential-upgrade path — after a successful login, if the
// stored hash predates your current cost parameters, re-derive it while the
// plaintext is still in hand — so raising the iteration count never forces a
// password reset.
//
//	go run ./examples/pwhash
//	curl -i -d 'username=alice&password=password123' localhost:3000/login
package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/pwhash"
	"github.com/malcolmston/passport/strategies/local"
)

// User is the application's user model. Note what it does *not* contain: a
// password field. Only the derived hash is stored, in a separate table below.
type User struct {
	ID   string
	Name string
}

// store is a toy user table. The value is the encoded pwhash string —
// "pbkdf2_sha256$600000$<salt>$<key>" — which is self-describing: it carries
// the algorithm, iteration count and salt, so nothing else needs storing.
type store struct {
	mu     sync.RWMutex
	users  map[string]User   // username -> user
	hashes map[string]string // username -> encoded pwhash
}

func newStore() *store {
	return &store{users: map[string]User{}, hashes: map[string]string{}}
}

// register derives and stores a hash for a new account. This is the only place
// a plaintext password enters the system on the write path.
func (s *store) register(username, password string, u User) error {
	encoded, err := pwhash.Hash(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = u
	s.hashes[username] = encoded
	return nil
}

// registerLegacy seeds an account whose hash was derived under old, weak
// parameters, so the upgrade path below has something to upgrade.
func (s *store) registerLegacy(username, password string, u User) error {
	encoded, err := pwhash.HashWithParams(password, pwhash.Params{
		Algorithm: pwhash.SHA1, Iterations: 1_000, SaltLength: 8, KeyLength: 20,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = u
	s.hashes[username] = encoded
	return nil
}

// authenticate checks a submitted password and, on success, transparently
// upgrades a stale hash.
func (s *store) authenticate(username, password string) (any, error) {
	s.mu.RLock()
	u, ok := s.users[username]
	encoded := s.hashes[username]
	s.mu.RUnlock()

	if !ok {
		// Derive against a throwaway hash anyway so that a request for an
		// unknown user costs roughly the same as one for a known user. Without
		// this, response timing leaks which usernames exist.
		_, _ = pwhash.Verify(password, decoyHash)
		return nil, local.ErrInvalidCredentials
	}

	valid, err := pwhash.Verify(password, encoded)
	if err != nil {
		// A hash we cannot parse is a hash we cannot trust: fail the login.
		// Never fall through to success on a decode error.
		log.Printf("corrupt stored hash for %q: %v", username, err)
		return nil, local.ErrInvalidCredentials
	}
	if !valid {
		return nil, local.ErrInvalidCredentials
	}

	// The password is correct and still in hand — the one moment we can
	// re-derive it. Upgrade the stored hash if it is weaker than today's
	// defaults.
	if pwhash.NeedsRehash(encoded, pwhash.DefaultParams()) {
		if upgraded, err := pwhash.Hash(password); err == nil {
			s.mu.Lock()
			s.hashes[username] = upgraded
			s.mu.Unlock()
			log.Printf("upgraded stored hash for %q to current parameters", username)
		}
	}

	return u, nil
}

// decoyHash is a valid encoding of a random password, used to equalize the
// cost of a login attempt for an unknown username.
var decoyHash string

func main() {
	var err error
	if decoyHash, err = pwhash.Hash("a password nobody has"); err != nil {
		log.Fatal(err)
	}

	db := newStore()
	if err := db.register("alice", "password123", User{ID: "1", Name: "Alice"}); err != nil {
		log.Fatal(err)
	}
	// Bob's credential predates the current cost settings; logging in as Bob
	// upgrades it in place.
	if err := db.registerLegacy("bob", "hunter2", User{ID: "2", Name: "Bob"}); err != nil {
		log.Fatal(err)
	}

	p := passport.New()
	p.Use(local.New(db.authenticate))
	p.SerializeUser(func(u any) (string, error) { return u.(User).ID, nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) {
		db.mu.RLock()
		defer db.mu.RUnlock()
		for _, u := range db.users {
			if u.ID == id {
				return u, nil
			}
		}
		return nil, nil
	})

	// Serve over TLS in production and turn this on; the session cookie is a
	// bearer credential and must not travel in the clear.
	// p.SecureCookies(true)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})

	mux.Handle("/login", p.Authenticate("local")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Logged in as " + passport.User(r).(User).Name))
		}),
	))

	mux.Handle("/profile", p.RequireLogin("/")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Profile of " + passport.User(r).(User).Name))
		}),
	))

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = p.LogOut(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	log.Println("listening on :3000 — try alice/password123 or bob/hunter2")
	log.Fatal(http.ListenAndServe(":3000", handler))
}

const page = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Hashed-password login</title></head>
<body>
  <h1>Sign in</h1>
  <form method="POST" action="/login">
    <label>Username <input name="username" value="alice" autocomplete="username"></label><br>
    <label>Password <input name="password" type="password" value="password123" autocomplete="current-password"></label><br>
    <button type="submit">Log in</button>
  </form>
  <p>Passwords are stored as PBKDF2-HMAC-SHA256 hashes, never in plaintext.</p>
  <p>Log in as <code>bob</code> / <code>hunter2</code> to watch a legacy hash get
     upgraded to the current parameters (see the server log).</p>
  <p><a href="/profile">View profile</a> &middot; <a href="/logout">Log out</a></p>
</body>
</html>`
