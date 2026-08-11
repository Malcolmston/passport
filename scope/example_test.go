package scope_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/malcolmston/passport/scope"
)

// ExampleParse reads the space-delimited scope value an OAuth provider returns
// in its token response and answers membership questions about it.
func ExampleParse() {
	granted := scope.Parse("openid  profile email")

	fmt.Println("count:  ", granted.Len())
	fmt.Println("email:  ", granted.Has("email"))
	fmt.Println("admin:  ", granted.Has("admin"))
	fmt.Println("rendered:", granted)

	// Output:
	// count:   3
	// email:   true
	// admin:   false
	// rendered: openid profile email
}

// ExampleSet_Has shows why membership is an exact token match. A substring
// check over the raw scope string would treat "readadmin" as granting "admin"
// and "user:read" as granting "user" — a privilege escalation. Has compares
// whole tokens, so both correctly report false.
func ExampleSet_Has() {
	granted := scope.Parse("readadmin user:read")

	fmt.Println("admin:    ", granted.Has("admin"))
	fmt.Println("user:     ", granted.Has("user"))
	fmt.Println("read:     ", granted.Has("read"))
	fmt.Println("readadmin:", granted.Has("readadmin"))
	fmt.Println("user:read:", granted.Has("user:read"))

	// Output:
	// admin:     false
	// user:      false
	// read:      false
	// readadmin: true
	// user:read: true
}

// ExampleSet_HasAll gates a handler on the scopes an access token actually
// carries. HasAll requires every listed scope; HasAny requires at least one.
func ExampleSet_HasAll() {
	granted := scope.Parse("repo:read repo:write")

	fmt.Println("can read and write:", granted.HasAll("repo:read", "repo:write"))
	fmt.Println("can also delete:   ", granted.HasAll("repo:read", "repo:delete"))
	fmt.Println("has any repo verb: ", granted.HasAny("repo:delete", "repo:read"))

	// Output:
	// can read and write: true
	// can also delete:    false
	// has any repo verb:  true
}

// ExampleSet_Contains checks a granted set against a required set — the usual
// shape of an authorization decision when the requirement is itself a scope
// list. Diff then reports exactly what is missing, which makes for an
// actionable error message.
func ExampleSet_Contains() {
	required := scope.New("openid", "email", "offline_access")
	granted := scope.Parse("openid email profile")

	fmt.Println("satisfied:", granted.Contains(required))
	fmt.Println("missing:  ", required.Diff(granted))
	fmt.Println("extra:    ", granted.Diff(required))

	// Output:
	// satisfied: false
	// missing:   offline_access
	// extra:     profile
}

// ExampleParseSep handles providers that deviate from RFC 6749's space
// delimiter. Facebook and LinkedIn use commas; passport-oauth2 exposes this as
// its scopeSeparator option.
func ExampleParseSep() {
	fb := scope.ParseSep("email, public_profile ,pages_show_list", ",")

	fmt.Println("parsed:", fb.Slice())
	fmt.Println("as wire value for a comma provider:", fb.Join(","))
	fmt.Println("as an RFC 6749 space-delimited value:", fb.String())

	// Output:
	// parsed: [email public_profile pages_show_list]
	// as wire value for a comma provider: email,public_profile,pages_show_list
	// as an RFC 6749 space-delimited value: email public_profile pages_show_list
}

// ExampleSet_String builds the scope parameter of an authorization URL.
// Insertion order is preserved, so the generated URL is stable across runs and
// diffs cleanly in tests and logs.
func ExampleSet_String() {
	requested := scope.New("openid").Add("profile", "email").Add("openid")

	q := url.Values{}
	q.Set("client_id", "abc123")
	q.Set("response_type", "code")
	q.Set("scope", requested.String())

	fmt.Println(q.Encode())

	// Output:
	// client_id=abc123&response_type=code&scope=openid+profile+email
}

// ExampleSet_Union combines a provider preset with the extra scopes an
// application asks for, without duplicating anything the preset already
// includes.
func ExampleSet_Union() {
	preset := scope.New("openid", "profile")
	extra := scope.Parse("email openid calendar.read")

	fmt.Println("union:       ", preset.Union(extra))
	fmt.Println("intersection:", preset.Intersection(extra))
	fmt.Println("only in extra:", extra.Diff(preset))

	// Output:
	// union:        openid profile email calendar.read
	// intersection: openid
	// only in extra: email calendar.read
}

// ExampleSet_Filter narrows a granted set down to one namespace, for instance
// to show a user which repository permissions an integration holds.
func ExampleSet_Filter() {
	granted := scope.Parse("repo:read repo:write user:email admin")

	repo := granted.Filter(func(s string) bool {
		return len(s) > 5 && s[:5] == "repo:"
	})
	fmt.Println(repo)

	// Output:
	// repo:read repo:write
}

// ExampleSet_MarshalText shows a Set round-tripping through JSON as a plain
// space-delimited string, matching how scopes appear in an OAuth token
// response body.
func ExampleSet_MarshalText() {
	type tokenResponse struct {
		AccessToken string    `json:"access_token"`
		Scope       scope.Set `json:"scope"`
	}

	body := []byte(`{"access_token":"tok_123","scope":"openid email"}`)

	var resp tokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		panic(err)
	}
	fmt.Println("has email:", resp.Scope.Has("email"))

	out, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))

	// Output:
	// has email: true
	// {"access_token":"tok_123","scope":"openid email"}
}

// ExampleSet_HasAny wires scopes into an HTTP middleware: the handler runs only
// when the request's token carries every required scope, and otherwise gets the
// 403 that RFC 6750 prescribes for an insufficient scope.
func ExampleSet_HasAny() {
	requireScopes := func(required ...string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				granted := scope.Parse(r.Header.Get("X-Token-Scope"))
				if !granted.HasAll(required...) {
					missing := scope.New(required...).Diff(granted)
					w.Header().Set("WWW-Authenticate",
						`Bearer error="insufficient_scope", scope="`+missing.String()+`"`)
					http.Error(w, "insufficient scope", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}

	guarded := requireScopes("repo:write")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") },
	))

	for _, tokenScope := range []string{"repo:read repo:write", "repo:read"} {
		req := httptest.NewRequest(http.MethodPost, "/repos/1", nil)
		req.Header.Set("X-Token-Scope", tokenScope)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		fmt.Printf("scope %q -> %d\n", tokenScope, rec.Code)
		if challenge := rec.Header().Get("WWW-Authenticate"); challenge != "" {
			fmt.Println("  challenge:", challenge)
		}
	}

	// A read-only token still satisfies a check that accepts either verb.
	fmt.Println("read-only has any:", scope.Parse("repo:read").HasAny("repo:read", "repo:write"))

	// Output:
	// scope "repo:read repo:write" -> 200
	// scope "repo:read" -> 403
	//   challenge: Bearer error="insufficient_scope", scope="repo:write"
	// read-only has any: true
}
