package passport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The vectors in this file are transcribed from Passport.js 0.7.0's own test
// suite (jaredhanson/passport):
//
//   test/authenticator.test.js   -> #use, #unuse, #serializeUser,
//                                    #deserializeUser, #transformAuthInfo
//   test/http/request.test.js    -> #login, #logout, #isAuthenticated
//
// Each Go case reproduces the exact known-answer assertion the upstream mocha
// suite makes, mapped onto this port's API. Values that JavaScript expresses as
// null/undefined/false are mapped as documented on the Serializer/Deserializer
// contracts: Go nil == JS undefined (defer to next layer), passport.Invalidate
// == JS null, and the boolean false == JS false (session invalidation).

type parityUser struct {
	ID       string
	Username string
}

// --- #serializeUser -------------------------------------------------------

func TestParitySerializeUser(t *testing.T) {
	user := parityUser{ID: "1", Username: "jared"}

	t.Run("without serializers", func(t *testing.T) {
		p := New()
		_, err := p.Serialize(user, nil)
		if !errors.Is(err, ErrFailedToSerialize) {
			t.Fatalf("want ErrFailedToSerialize, got %v", err)
		}
	})

	t.Run("with one serializer", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(u any, _ *http.Request) (any, error) {
			return u.(parityUser).ID, nil
		})
		got, err := p.Serialize(user, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "1" {
			t.Fatalf("want %q, got %v", "1", got)
		}
	})

	t.Run("serializes to 0 (valid)", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) { return 0, nil })
		got, err := p.Serialize(user, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Fatalf("want 0, got %v", got)
		}
	})

	t.Run("serializes to false (error)", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) { return false, nil })
		if _, err := p.Serialize(user, nil); !errors.Is(err, ErrFailedToSerialize) {
			t.Fatalf("want ErrFailedToSerialize, got %v", err)
		}
	})

	t.Run("serializes to null/undefined (error)", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) { return nil, nil })
		if _, err := p.Serialize(user, nil); !errors.Is(err, ErrFailedToSerialize) {
			t.Fatalf("want ErrFailedToSerialize, got %v", err)
		}
	})

	t.Run("serializer returns error", func(t *testing.T) {
		p := New()
		want := errors.New("something went wrong")
		p.AddSerializer(func(any, *http.Request) (any, error) { return nil, want })
		_, err := p.Serialize(user, nil)
		if err == nil || err.Error() != "something went wrong" {
			t.Fatalf("want %q, got %v", want, err)
		}
	})

	t.Run("serializer panics", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) {
			panic(errors.New("something went horribly wrong"))
		})
		_, err := p.Serialize(user, nil)
		if err == nil || err.Error() != "something went horribly wrong" {
			t.Fatalf("want recovered panic error, got %v", err)
		}
	})

	t.Run("three serializers, first passes, second serializes", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddSerializer(func(any, *http.Request) (any, error) { return "two", nil })
		p.AddSerializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Serialize(user, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "two" {
			t.Fatalf("want %q, got %v", "two", got)
		}
	})

	t.Run("three serializers, first passes, second defers by nil", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddSerializer(func(any, *http.Request) (any, error) { return nil, nil })
		p.AddSerializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Serialize(user, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "three" {
			t.Fatalf("want %q, got %v", "three", got)
		}
	})

	t.Run("serializer that takes request as argument", func(t *testing.T) {
		p := New()
		p.AddSerializer(func(u any, r *http.Request) (any, error) {
			if r == nil || r.URL.Path != "/foo" {
				return nil, errors.New("incorrect req argument")
			}
			return u.(parityUser).ID, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/foo", nil)
		got, err := p.Serialize(user, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "1" {
			t.Fatalf("want %q, got %v", "1", got)
		}
	})
}

// --- #deserializeUser -----------------------------------------------------

func TestParityDeserializeUser(t *testing.T) {
	stored := parityUser{ID: "1", Username: "jared"}

	t.Run("without deserializers", func(t *testing.T) {
		p := New()
		if _, err := p.Deserialize(stored, nil); !errors.Is(err, ErrFailedToDeserialize) {
			t.Fatalf("want ErrFailedToDeserialize, got %v", err)
		}
	})

	t.Run("with one deserializer", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(obj any, _ *http.Request) (any, error) {
			return obj.(parityUser).Username, nil
		})
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "jared" {
			t.Fatalf("want %q, got %v", "jared", got)
		}
	})

	t.Run("deserializes to false (invalidate)", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return false, nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != false {
			t.Fatalf("want false (invalidate), got %v", got)
		}
	})

	t.Run("deserializes to null (invalidate)", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return Invalidate, nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != false {
			t.Fatalf("want false (invalidate), got %v", got)
		}
	})

	t.Run("deserializes to undefined (error)", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, nil })
		if _, err := p.Deserialize(stored, nil); !errors.Is(err, ErrFailedToDeserialize) {
			t.Fatalf("want ErrFailedToDeserialize, got %v", err)
		}
	})

	t.Run("deserializer returns error", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) {
			return nil, errors.New("something went wrong")
		})
		_, err := p.Deserialize(stored, nil)
		if err == nil || err.Error() != "something went wrong" {
			t.Fatalf("want error, got %v", err)
		}
	})

	t.Run("deserializer panics", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) {
			panic(errors.New("something went horribly wrong"))
		})
		_, err := p.Deserialize(stored, nil)
		if err == nil || err.Error() != "something went horribly wrong" {
			t.Fatalf("want recovered panic error, got %v", err)
		}
	})

	t.Run("three deserializers, first passes, second deserializes", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return "two", nil })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "two" {
			t.Fatalf("want %q, got %v", "two", got)
		}
	})

	t.Run("three deserializers, first passes, second defers by nil", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, nil })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "three" {
			t.Fatalf("want %q, got %v", "three", got)
		}
	})

	t.Run("three deserializers, first passes, second invalidates by false", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return false, nil })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != false {
			t.Fatalf("want false (invalidate), got %v", got)
		}
	})

	t.Run("three deserializers, first passes, second invalidates by null", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(any, *http.Request) (any, error) { return nil, ErrPass })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return Invalidate, nil })
		p.AddDeserializer(func(any, *http.Request) (any, error) { return "three", nil })
		got, err := p.Deserialize(stored, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != false {
			t.Fatalf("want false (invalidate), got %v", got)
		}
	})

	t.Run("deserializer that takes request as argument", func(t *testing.T) {
		p := New()
		p.AddDeserializer(func(obj any, r *http.Request) (any, error) {
			if r == nil || r.URL.Path != "/foo" {
				return nil, errors.New("incorrect req argument")
			}
			return obj.(parityUser).Username, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/foo", nil)
		got, err := p.Deserialize(stored, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "jared" {
			t.Fatalf("want %q, got %v", "jared", got)
		}
	})
}

// --- #transformAuthInfo ---------------------------------------------------

func TestParityTransformAuthInfo(t *testing.T) {
	t.Run("without transforms returns info unchanged", func(t *testing.T) {
		p := New()
		info := map[string]any{"clientId": "1", "scope": "write"}
		got, err := p.TransformAuthInfo(info, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m, ok := got.(map[string]any)
		if !ok || len(m) != 2 || m["clientId"] != "1" || m["scope"] != "write" {
			t.Fatalf("info not returned unchanged: %v", got)
		}
	})

	t.Run("with one transform", func(t *testing.T) {
		p := New()
		p.AddInfoTransformer(func(info any, _ *http.Request) (any, error) {
			m := info.(map[string]any)
			return map[string]any{"clientId": m["clientId"], "client": map[string]any{"name": "Foo"}}, nil
		})
		got, err := p.TransformAuthInfo(map[string]any{"clientId": "1", "scope": "write"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := got.(map[string]any)
		if m["clientId"] != "1" {
			t.Fatalf("want clientId=1, got %v", m["clientId"])
		}
		client, ok := m["client"].(map[string]any)
		if !ok || client["name"] != "Foo" {
			t.Fatalf("want client.name=Foo, got %v", m["client"])
		}
	})
}

// --- #use / #unuse --------------------------------------------------------

type namedStrategy struct{ name string }

func (s namedStrategy) Name() string                         { return s.name }
func (s namedStrategy) Authenticate(*Context, *http.Request) {}

func TestParityUseUnuse(t *testing.T) {
	t.Run("with instance name", func(t *testing.T) {
		p := New()
		p.Use(namedStrategy{name: "default"})
		if _, ok := p.strategies["default"]; !ok {
			t.Fatalf("strategy not registered under instance name")
		}
	})

	t.Run("with registered name overriding instance name", func(t *testing.T) {
		p := New()
		p.UseNamed("bar", namedStrategy{name: "default"})
		if _, ok := p.strategies["bar"]; !ok {
			t.Fatalf("strategy not registered under bar")
		}
		if _, ok := p.strategies["default"]; ok {
			t.Fatalf("strategy should not be registered under its instance name")
		}
	})

	t.Run("unuse", func(t *testing.T) {
		p := New()
		p.UseNamed("one", namedStrategy{name: "one"})
		p.UseNamed("two", namedStrategy{name: "two"})
		p.Unuse("one")
		if _, ok := p.strategies["one"]; ok {
			t.Fatalf("one should be unregistered")
		}
		if _, ok := p.strategies["two"]; !ok {
			t.Fatalf("two should still be registered")
		}
	})

	t.Run("use panics when lacking a name", func(t *testing.T) {
		p := New()
		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("expected panic for nameless strategy")
			}
		}()
		p.Use(namedStrategy{name: ""})
	})
}

// --- #login / #logout / #isAuthenticated ----------------------------------

// withState runs fn inside a request that has passport's per-request state
// installed by Initialize(), the precondition for LogIn/LogOut/IsAuthenticated.
func withState(p *Passport, fn func(w http.ResponseWriter, r *http.Request)) {
	h := p.Initialize()(http.HandlerFunc(fn))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
}

func TestParityLoginLogout(t *testing.T) {
	t.Run("login without a session establishes an authenticated user", func(t *testing.T) {
		p := New() // no SerializeUser -> stateless login path
		withState(p, func(w http.ResponseWriter, r *http.Request) {
			user := parityUser{ID: "1", Username: "root"}
			if err := p.LogIn(w, r, user); err != nil {
				t.Fatalf("login error: %v", err)
			}
			if !IsAuthenticated(r) {
				t.Fatalf("want authenticated after login")
			}
			got, ok := User(r).(parityUser)
			if !ok || got.ID != "1" || got.Username != "root" {
				t.Fatalf("user not set correctly: %v", User(r))
			}
		})
	})

	t.Run("login with a serializer stores the serialized id in the session", func(t *testing.T) {
		p := New()
		p.SerializeUser(func(u any) (string, error) { return u.(parityUser).ID, nil })
		withState(p, func(w http.ResponseWriter, r *http.Request) {
			if err := p.LogIn(w, r, parityUser{ID: "1", Username: "root"}); err != nil {
				t.Fatalf("login error: %v", err)
			}
			st := stateFrom(r)
			raw, ok := st.session.Get(p.userKey)
			if !ok || raw != "1" {
				t.Fatalf("serialized user id not stored: %v", raw)
			}
		})
	})

	t.Run("logout clears the user and de-authenticates", func(t *testing.T) {
		p := New()
		withState(p, func(w http.ResponseWriter, r *http.Request) {
			_ = p.LogIn(w, r, parityUser{ID: "1", Username: "root"})
			if err := p.LogOut(w, r); err != nil {
				t.Fatalf("logout error: %v", err)
			}
			if IsAuthenticated(r) {
				t.Fatalf("want not authenticated after logout")
			}
			if User(r) != nil {
				t.Fatalf("want nil user after logout, got %v", User(r))
			}
		})
	})
}

func TestParityIsAuthenticated(t *testing.T) {
	t.Run("with a user", func(t *testing.T) {
		p := New()
		withState(p, func(w http.ResponseWriter, r *http.Request) {
			_ = p.LogIn(w, r, parityUser{ID: "1", Username: "root"})
			if !IsAuthenticated(r) {
				t.Fatalf("want authenticated")
			}
		})
	})

	t.Run("without a user", func(t *testing.T) {
		p := New()
		withState(p, func(_ http.ResponseWriter, r *http.Request) {
			if IsAuthenticated(r) {
				t.Fatalf("want not authenticated")
			}
		})
	})

	t.Run("without initialize middleware", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if IsAuthenticated(req) {
			t.Fatalf("want not authenticated without state")
		}
		if User(req) != nil {
			t.Fatalf("want nil user without state")
		}
	})
}
