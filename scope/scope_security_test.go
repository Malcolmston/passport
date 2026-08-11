package scope

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMembershipIsNotSubstringBased is the load-bearing security property of
// this package. Authorization decisions are made by asking whether a granted
// scope set contains a required scope; if that check were implemented as a
// substring search over the raw space-delimited string (the tempting shortcut),
// a token granted "readadmin" or "user:read" would satisfy a gate on "admin" or
// "user" and escalate privilege. Every case below is a string that a
// strings.Contains check would wrongly accept.
func TestMembershipIsNotSubstringBased(t *testing.T) {
	tests := []struct {
		name    string
		granted string
		probe   string
	}{
		{"scope is a prefix of a granted token", "readadmin", "read"},
		{"scope is a suffix of a granted token", "superadmin", "admin"},
		{"scope is an infix of a granted token", "xx-admin-yy", "admin"},
		{"colon-namespaced prefix", "user:read", "user"},
		{"colon-namespaced suffix", "user:read", "read"},
		{"dot-namespaced prefix", "repo.write", "repo"},
		{"spans the delimiter between two tokens", "read write", "read w"},
		{"whole string as one probe", "openid profile", "openid profile"},
		{"trailing colon", "admin:", "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Parse(tt.granted)

			// Sanity: this is precisely the naive check we must not behave like.
			if !strings.Contains(tt.granted, tt.probe) {
				t.Fatalf("bad test case: %q does not contain %q", tt.granted, tt.probe)
			}

			if s.Has(tt.probe) {
				t.Errorf("Has(%q) = true for granted %q; membership must be an exact token match", tt.probe, tt.granted)
			}
			if s.HasAll(tt.probe) {
				t.Errorf("HasAll(%q) = true for granted %q", tt.probe, tt.granted)
			}
			if s.HasAny(tt.probe) {
				t.Errorf("HasAny(%q) = true for granted %q", tt.probe, tt.granted)
			}
			if s.Contains(New(tt.probe)) {
				t.Errorf("Contains(%q) = true for granted %q", tt.probe, tt.granted)
			}
		})
	}
}

// TestMembershipIsCaseSensitive pins that scope tokens are compared byte-for-
// byte. OAuth scope values are case-sensitive strings, so "Admin" must not
// satisfy a gate on "admin" (nor the reverse).
func TestMembershipIsCaseSensitive(t *testing.T) {
	s := Parse("Admin Read")
	for _, probe := range []string{"admin", "ADMIN", "read", "rEaD"} {
		if s.Has(probe) {
			t.Errorf("Has(%q) = true for granted %q; comparison must be case-sensitive", probe, s)
		}
	}
	if !s.HasAll("Admin", "Read") {
		t.Error("exact-case tokens should be present")
	}
}

func TestHasAllHasAny(t *testing.T) {
	s := Parse("openid profile email")

	tests := []struct {
		name   string
		probes []string
		all    bool
		any    bool
	}{
		{"no probes", nil, true, false},
		{"single present", []string{"openid"}, true, true},
		{"single absent", []string{"admin"}, false, false},
		{"all present", []string{"openid", "email"}, true, true},
		{"one absent", []string{"openid", "admin"}, false, true},
		{"all absent", []string{"admin", "root"}, false, false},
		{"duplicate probes", []string{"email", "email"}, true, true},
		{"empty token probe", []string{""}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.HasAll(tt.probes...); got != tt.all {
				t.Errorf("HasAll(%q) = %v, want %v", tt.probes, got, tt.all)
			}
			if got := s.HasAny(tt.probes...); got != tt.any {
				t.Errorf("HasAny(%q) = %v, want %v", tt.probes, got, tt.any)
			}
		})
	}
}

// TestZeroValueIsSafe pins that the documented-unusable zero value still
// answers read-only queries instead of panicking on a nil map. An
// authorization gate that panics is an outage; one that reports "no scopes" is
// correct fail-closed behaviour.
func TestZeroValueIsSafe(t *testing.T) {
	var s Set
	if s.Has("admin") {
		t.Error("zero value Has = true, want false")
	}
	if !s.IsEmpty() {
		t.Error("zero value IsEmpty = false, want true")
	}
	if s.Len() != 0 {
		t.Errorf("zero value Len = %d, want 0", s.Len())
	}
	if s.String() != "" {
		t.Errorf("zero value String = %q, want empty", s.String())
	}
	if s.HasAny("a") {
		t.Error("zero value HasAny = true, want false")
	}
	if !s.HasAll() {
		t.Error("zero value HasAll() with no probes = false, want true")
	}
	if got := s.Add("openid").String(); got != "openid" {
		t.Errorf("Add on zero value = %q, want %q", got, "openid")
	}
	if s.Clone().Len() != 0 {
		t.Error("Clone of zero value is not empty")
	}
	if !s.Contains(New()) {
		t.Error("zero value should contain the empty set")
	}
	if s.Contains(New("a")) {
		t.Error("zero value should not contain a non-empty set")
	}
}

func TestParseSep(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		sep  string
		want []string
	}{
		{"comma separated", "email,public_profile", ",", []string{"email", "public_profile"}},
		{"comma with spaces", "email, public_profile , pages", ",", []string{"email", "public_profile", "pages"}},
		{"empty tokens dropped", "a,,b,", ",", []string{"a", "b"}},
		{"duplicates collapsed", "a,b,a", ",", []string{"a", "b"}},
		{"empty separator falls back to whitespace", "a  b\tc", "", []string{"a", "b", "c"}},
		{"empty input", "", ",", nil},
		{"whitespace-only input", "   ", ",", nil},
		{"separator absent from input", "openid profile", ",", []string{"openid profile"}},
		{"multi-char separator", "a::b::c", "::", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSep(tt.raw, tt.sep).Slice()
			if len(got) != len(tt.want) {
				t.Fatalf("ParseSep(%q, %q) = %q, want %q", tt.raw, tt.sep, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParseSep(%q, %q) = %q, want %q", tt.raw, tt.sep, got, tt.want)
				}
			}
		})
	}
}

func TestJoinRoundTripsWithParseSep(t *testing.T) {
	for _, sep := range []string{" ", ",", "::"} {
		orig := New("openid", "profile", "email")
		round := ParseSep(orig.Join(sep), sep)
		if !round.Equal(orig) {
			t.Errorf("round trip with sep %q gave %q, want %q", sep, round, orig)
		}
	}
}

func TestTextMarshalling(t *testing.T) {
	type request struct {
		Scope Set `json:"scope"`
	}

	got, err := json.Marshal(request{Scope: New("openid", "profile")})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != `{"scope":"openid profile"}` {
		t.Errorf("Marshal = %s, want {\"scope\":\"openid profile\"}", got)
	}

	var back request
	if err := json.Unmarshal([]byte(`{"scope":"email  openid email"}`), &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !back.Scope.Equal(New("email", "openid")) {
		t.Errorf("Unmarshal gave %q, want \"email openid\"", back.Scope)
	}

	// An empty wire value must yield a usable (not nil-map) empty Set.
	var empty request
	if err := json.Unmarshal([]byte(`{"scope":""}`), &empty); err != nil {
		t.Fatalf("Unmarshal empty: %v", err)
	}
	if !empty.Scope.IsEmpty() {
		t.Error("empty scope string did not unmarshal to an empty set")
	}
	if got := empty.Scope.Add("openid").String(); got != "openid" {
		t.Errorf("Add after unmarshalling empty = %q, want %q", got, "openid")
	}
}

// TestOperationsDoNotMutateReceiver pins the documented value semantics: every
// combinator returns a new Set. A shared "granted scopes" value being mutated
// by a caller's Remove would be a cross-request privilege bug.
func TestOperationsDoNotMutateReceiver(t *testing.T) {
	orig := New("a", "b", "c")
	const want = "a b c"

	orig.Add("d")
	orig.Remove("a")
	orig.Union(New("e"))
	orig.Intersection(New("a"))
	orig.Diff(New("b"))
	orig.Filter(func(string) bool { return false })
	orig.Clone().Add("z")
	orig.Sorted()
	orig.Slice()[0] = "mutated"

	if got := orig.String(); got != want {
		t.Errorf("receiver mutated: got %q, want %q", got, want)
	}
}

func TestClone(t *testing.T) {
	orig := New("a", "b")
	clone := orig.Clone()
	if !clone.Equal(orig) {
		t.Fatal("clone is not equal to the original")
	}
	if grown := clone.Add("c"); orig.Has("c") || !grown.Has("c") {
		t.Error("mutating a clone affected the original")
	}
}

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		name string
		set  Set
		want bool
	}{
		{"new with no args", New(), true},
		{"parse empty", Parse(""), true},
		{"parse whitespace", Parse("  \t\n "), true},
		{"parse empty tokens only", New("", ""), true},
		{"non-empty", New("a"), false},
		{"emptied by Remove", New("a").Remove("a"), true},
		{"emptied by Filter", New("a").Filter(func(string) bool { return false }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.set.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}
