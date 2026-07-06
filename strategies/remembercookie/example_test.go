package remembercookie_test

import (
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/remembercookie"
)

// ExampleNew shows the full wiring for persistent "remember me" login using the
// selector/validator cookie scheme. On each request the strategy reads the
// "remember" cookie ("selector:validator"), resolves the selector to a stored
// token hash, and compares the validator against it in constant time.
func ExampleNew() {
	// A stored remember-me token: selector -> (user, validator hash).
	type token struct {
		user      string
		validator string
	}
	tokens := map[string]token{
		"sel123": {user: "alice", validator: "secret-validator"},
	}

	p := passport.New()

	p.Use(remembercookie.New(remembercookie.Options{
		Lookup: func(selector string) (user any, tokenHash string, err error) {
			t, ok := tokens[selector]
			if !ok {
				return nil, "", nil
			}
			return t.user, t.validator, nil
		},
	}))
	p.SerializeUser(func(u any) (string, error) { return u.(string), nil })
	p.DeserializeUser(func(id string, _ *http.Request) (any, error) { return id, nil })

	mux := http.NewServeMux()

	// The strategy Pass()es when there is no remember cookie, so the handler
	// still runs — passport.User(r) is nil for anonymous requests.
	mux.Handle("/", p.Authenticate("remember-me")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u := passport.User(r); u != nil {
				_, _ = w.Write([]byte("welcome back, " + u.(string)))
				return
			}
			_, _ = w.Write([]byte("hello, stranger"))
		}),
	))

	handler := passport.Chain(mux, p.Initialize(), p.Session())
	log.Fatal(http.ListenAndServe(":3000", handler))
}
