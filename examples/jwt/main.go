// Command jwt demonstrates stateless API authentication: a login endpoint
// exchanges username/password for a signed HS256 token, and the API endpoints
// authenticate each request from the Authorization header with no session and
// no server-side state at all.
//
// The key detail is passport.Options{Session: passport.NoSession()} on the guarded routes.
// Token auth must not establish a session cookie: doing so would attach an
// ambient credential to the browser and reintroduce the CSRF surface that
// bearer tokens exist to avoid.
//
//	go run ./examples/jwt
//	TOKEN=$(curl -s -d 'username=alice&password=password123' localhost:3000/login | sed 's/.*"token":"//;s/".*//')
//	curl -H "Authorization: Bearer $TOKEN" localhost:3000/api/me
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/pwhash"
	"github.com/malcolmston/passport/scope"
	"github.com/malcolmston/passport/strategies/jwt"
	"github.com/malcolmston/passport/strategies/local"
)

// secret signs and verifies tokens. In production load it from the
// environment or a secret manager — never hard-code it.
var secret = []byte("replace-me-with-a-real-secret")

// User is the application's user model.
type User struct {
	ID    string
	Name  string
	Scope scope.Set
}

// account pairs a user with its stored password hash.
type account struct {
	User User
	Hash string
}

var accounts map[string]account

func main() {
	// Seed the user table with hashed passwords.
	aliceHash, err := pwhash.Hash("password123")
	if err != nil {
		log.Fatal(err)
	}
	readerHash, err := pwhash.Hash("readonly")
	if err != nil {
		log.Fatal(err)
	}
	accounts = map[string]account{
		"alice":  {User{ID: "1", Name: "Alice", Scope: scope.New("api:read", "api:write")}, aliceHash},
		"reader": {User{ID: "2", Name: "Reader", Scope: scope.New("api:read")}, readerHash},
	}

	p := passport.New()

	// Strategy 1: local, used only by /login to mint a token.
	p.Use(local.New(func(username, password string) (any, error) {
		acct, ok := accounts[username]
		if !ok {
			return nil, local.ErrInvalidCredentials
		}
		valid, err := pwhash.Verify(password, acct.Hash)
		if err != nil || !valid {
			return nil, local.ErrInvalidCredentials
		}
		return acct.User, nil
	}))

	// Strategy 2: jwt, used by every API route. The verify function turns
	// validated claims back into a user; returning (nil, nil) rejects the
	// token, so a token for a deleted account stops working immediately.
	p.Use(jwt.New(secret, func(c jwt.Claims) (any, error) {
		for _, acct := range accounts {
			if acct.User.ID == c.Subject() {
				u := acct.User
				// Trust the scopes in the token, intersected with what the
				// account may hold today — a token can never grant more than
				// the account currently has.
				granted, _ := c["scope"].(string)
				u.Scope = scope.Parse(granted).Intersection(acct.User.Scope)
				return u, nil
			}
		}
		return nil, nil
	}))

	mux := http.NewServeMux()

	// POST /login — exchange credentials for a token. Session:false because no
	// cookie should be set; the client holds the token instead.
	mux.Handle("/login", p.Authenticate("local", passport.Options{Session: passport.NoSession()})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(User)
			now := time.Now()
			token, err := jwt.Sign(secret, jwt.Claims{
				"sub":   u.ID,
				"name":  u.Name,
				"scope": u.Scope.String(),
				"iat":   now.Unix(),
				"exp":   now.Add(time.Hour).Unix(),
			})
			if err != nil {
				http.Error(w, "could not issue token", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"token":      token,
				"token_type": "Bearer",
				"expires_in": int((time.Hour).Seconds()),
				"scope":      u.Scope.String(),
			})
		}),
	))

	// GET /api/me — any valid token.
	mux.Handle("/api/me", p.Authenticate("jwt", passport.Options{Session: passport.NoSession()})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := passport.User(r).(User)
			writeJSON(w, http.StatusOK, map[string]any{
				"id": u.ID, "name": u.Name, "scope": u.Scope.String(),
			})
		}),
	))

	// POST /api/items — needs the api:write scope on top of a valid token.
	mux.Handle("/api/items", p.Authenticate("jwt", passport.Options{Session: passport.NoSession()})(
		requireScope("api:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{
				"created_by": passport.User(r).(User).Name,
			})
		})),
	))

	// Only Initialize is needed: there is no Session() middleware because
	// there are no sessions to restore.
	handler := passport.Chain(mux, p.Initialize())

	log.Println("listening on :3000 — POST /login with alice/password123 or reader/readonly")
	log.Fatal(http.ListenAndServe(":3000", handler))
}

// requireScope gates a handler on the scopes carried by the authenticated
// token. Authentication ("who are you") and authorization ("may you do this")
// are separate steps: the jwt strategy answers the first, this answers the
// second, and a 403 — not a 401 — is the right response when a valid token
// simply lacks a permission.
func requireScope(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := passport.User(r).(User)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Exact token matching — never a substring check on the raw scope
			// string, which would let "api:readonly" satisfy "api:read".
			if !u.Scope.HasAll(required...) {
				missing := scope.New(required...).Diff(u.Scope)
				w.Header().Set("WWW-Authenticate",
					`Bearer error="insufficient_scope", scope="`+missing.String()+`"`)
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":   "insufficient_scope",
					"missing": missing.Slice(),
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing response: %v", err)
	}
}
